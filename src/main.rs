mod cache;
mod whitelist;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use clap::Parser;
use nix_archive::nar;
use nix_derivation::{NixHash, StoreDir, StorePath};
use nix_narinfo::{Compression, NarInfo};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use whitelist::Whitelist;

#[derive(Parser)]
#[command(name = "substituter-api", version, about)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Allow-list rule (repeatable): host, `*.sub.domain`, scheme://host, :port, /path.
    #[arg(long = "allow", value_name = "RULE")]
    allow: Vec<String>,

    /// File with one allow-list rule per line (`#` comments allowed).
    #[arg(long = "allow-file")]
    allow_file: Option<PathBuf>,

    /// SQLite state file (defaults to ./substituter-api.sqlite).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Store directory advertised in `.narinfo` files.
    #[arg(long, default_value = "/nix/store")]
    store_dir: String,

    /// Upstream timeout, in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
}

#[derive(Clone)]
struct App {
    whitelist: Arc<Whitelist>,
    client: reqwest::Client,
    cache: Arc<cache::Cache>,
    store_dir: StoreDir,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Cli::parse();
    let mut rules = args.allow.clone();
    if let Some(path) = &args.allow_file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        rules.extend(
            text.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
                .filter(|l| !l.is_empty()),
        );
    }
    let whitelist = Arc::new(Whitelist::new(&rules, rules.is_empty())?);

    let db = args
        .db
        .clone()
        .unwrap_or_else(|| "substituter-api.sqlite".into());
    let cache = Arc::new(cache::Cache::open(&db)?);

    let wl = whitelist.clone();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                attempt.stop()
            } else if wl.allows(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("redirect target is not allow-listed")
            }
        }))
        .timeout(Duration::from_secs(args.timeout))
        .build()
        .context("building http client")?;

    let state = App {
        whitelist,
        client,
        cache,
        store_dir: StoreDir::new(args.store_dir.clone())
            .with_context(|| format!("invalid store dir {:?}", args.store_dir))?,
    };

    let app = Router::new()
        .route("/notify", post(notify))
        .route("/nix-cache-info", get(cache_info))
        .route("/nar/{*path}", get(nar_body))
        .route("/{file}", get(narinfo))
        .with_state(state);

    let addr: SocketAddr = args.listen.parse().context("parsing --listen")?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    info!("listening on http://{addr}");
    axum::serve(listener, app).await.context("server error")
}

async fn notify(
    State(state): State<App>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (path, url) = parse_notify(&String::from_utf8_lossy(&body), &query)?;
    store_hash(&basename_of(&path))
        .ok_or_else(|| ApiError::bad_request(format!("not a store path: {path:?}")))?;
    resolve(&state, &url)?;

    let cache = state.cache.clone();
    let (p, u) = (path.clone(), url.clone());
    tokio::task::spawn_blocking(move || cache.record(&p, &u))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
    info!("registered {path} -> {url}");
    Ok(text(StatusCode::OK, "ok\n"))
}

async fn cache_info(State(state): State<App>) -> Response {
    text(
        StatusCode::OK,
        &format!(
            "StoreDir: {}\nWantMassQuery: 1\nPriority: 30\n",
            state.store_dir
        ),
    )
}

async fn narinfo(State(state): State<App>, Path(file): Path<String>) -> Result<Response, ApiError> {
    let stem = file
        .strip_suffix(".narinfo")
        .ok_or_else(|| ApiError::not_found("not found"))?;
    let (path, url) = lookup(&state, stem).await?;
    let store_path = StorePath::from_basename(basename_of(&path).as_bytes())
        .map_err(|e| ApiError::internal(format!("registered path {path:?}: {e}")))?;
    let content = fetch(&state, &url).await?;

    let nar_hash = nar::hash_regular(&content, false);
    let digest = NixHash::Sha256(nar_hash.sha256);
    let info = NarInfo::builder_in(
        state.store_dir.clone(),
        store_path.clone(),
        format!("nar/{}.nar", store_path.to_basename()),
        digest.clone(),
        nar_hash.size,
    )
    .compression(Compression::None)
    .file_hash(Some(digest))
    .file_size(Some(nar_hash.size))
    .build()
    .map_err(|e| ApiError::internal(format!("narinfo: {e}")))?;

    Ok(bytes(
        StatusCode::OK,
        "text/x-nix-narinfo",
        Bytes::from(info.to_canonical_bytes()),
    ))
}

async fn nar_body(
    State(state): State<App>,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let stem = file.strip_suffix(".nar").unwrap_or(&file);
    let (_, url) = lookup(&state, stem).await?;
    let content = fetch(&state, &url).await?;
    let mut nar = Vec::new();
    nar::encode_regular(&mut nar, &content, false)
        .map_err(|e| ApiError::internal(format!("encoding NAR: {e}")))?;
    Ok(bytes(
        StatusCode::OK,
        "application/x-nix-nar",
        Bytes::from(nar),
    ))
}

async fn lookup(state: &App, basename: &str) -> Result<(String, String), ApiError> {
    let hash = store_hash(basename).ok_or_else(|| ApiError::not_found("not a store path"))?;
    let cache = state.cache.clone();
    let dir = state.store_dir.as_str().to_string();
    let h = hash.to_string();
    tokio::task::spawn_blocking(move || cache.lookup(&dir, &h))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("no URL registered for {hash}")))
}

fn resolve(state: &App, url: &str) -> Result<Url, ApiError> {
    let parsed = Url::parse(url).map_err(|e| ApiError::bad_request(format!("bad URL: {e}")))?;
    if !state.whitelist.allows(&parsed) {
        return Err(ApiError::forbidden(format!("not allow-listed: {url}")));
    }
    Ok(parsed)
}

async fn fetch(state: &App, url: &str) -> Result<Bytes, ApiError> {
    let parsed = resolve(state, url)?;
    let resp = state
        .client
        .get(parsed)
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("upstream: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_gateway(format!("upstream {}", resp.status())));
    }
    resp.bytes()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("reading upstream: {e}")))
}

fn parse_notify(text: &str, query: &HashMap<String, String>) -> Result<(String, String), ApiError> {
    let text = text.trim();
    if text.starts_with('{')
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(text)
        && let (Some(path), Some(url)) = (
            v.get("path").and_then(|x| x.as_str()),
            v.get("url").and_then(|x| x.as_str()),
        )
    {
        return Ok((path.to_string(), url.to_string()));
    }
    let mut words = text.split_whitespace();
    if let (Some(a), Some(b)) = (words.next(), words.next()) {
        let (path, url) = if a.starts_with('/') { (a, b) } else { (b, a) };
        return Ok((path.to_string(), url.to_string()));
    }
    if let (Some(path), Some(url)) = (query.get("path"), query.get("url")) {
        return Ok((path.clone(), url.clone()));
    }
    Err(ApiError::bad_request("expected {\"path\":...,\"url\":...}"))
}

fn store_hash(basename: &str) -> Option<&str> {
    let bytes = basename.as_bytes();
    (bytes.len() == 32 || (bytes.len() >= 33 && bytes[32] == b'-'))
        .then(|| basename.get(..32))
        .flatten()
}

fn basename_of(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn text(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.to_string(),
    )
        .into_response()
}

fn bytes(status: StatusCode, content_type: &str, body: Bytes) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, content_type.to_string())],
        body,
    )
        .into_response()
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    msg: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError {
            status,
            msg: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    fn bad_gateway(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, msg)
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        text(self.status, &format!("{}\n", self.msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_basename() {
        let h = "0123456789abcdfghijklmnpqrsvwxyz";
        assert_eq!(store_hash(&format!("{h}-name")), Some(h));
        assert_eq!(store_hash(h), Some(h));
        assert_eq!(store_hash("nope"), None);
        assert_eq!(basename_of("/nix/store/abc-def"), "abc-def");
    }

    #[test]
    fn notify_body() {
        let q = HashMap::new();
        let (p, u) = parse_notify(r#"{"path":"/nix/store/x","url":"https://e.com/"}"#, &q).unwrap();
        assert_eq!((p.as_str(), u.as_str()), ("/nix/store/x", "https://e.com/"));
    }
}
