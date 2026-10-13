mod cache;
mod whitelist;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use nix_archive::nar;
use nix_derivation::{NixHash, StoreDir, StorePath};
use nix_narinfo::{Compression, NarInfo};
use tokio::io::AsyncWriteExt as _;
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

    /// SQLite state file (defaults to $STATE_DIRECTORY, else ./).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Blob cache directory (defaults to $STATE_DIRECTORY/cache, else ./cache).
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Blob cache budget, in bytes; least-recently-used entries are evicted beyond it.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    cache_max_size: u64,

    /// Store directory advertised in `.narinfo` files.
    #[arg(long, default_value = "/nix/store")]
    store_dir: String,

    /// Nix binary-cache signing key; generated if missing (defaults to $STATE_DIRECTORY, else ./).
    #[arg(long)]
    sign_key: Option<PathBuf>,

    /// Upstream timeout, in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
}

struct Signer {
    name: String,
    key: SigningKey,
}

impl Signer {
    fn load_or_generate(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).context("generating randomness")?;
        let key = SigningKey::from_bytes(&seed);
        let name = "substituter-api-1".to_string();

        write_secret(path, &format_key(&name, &key.to_keypair_bytes()))?;
        let public = format_key(&name, &key.verifying_key().to_bytes());
        let public_path = path.with_extension("pub");
        std::fs::write(&public_path, &public)
            .with_context(|| format!("writing {}", public_path.display()))?;

        info!("generated signing key {}", path.display());
        info!("public key ({}): {public}", public_path.display());

        Ok(Signer { name, key })
    }

    fn load(path: &PathBuf) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let (name, b64) = text
            .trim()
            .split_once(':')
            .context("expected `<name>:<base64>`")?;
        let raw: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be 64 bytes"))?;
        Ok(Signer {
            name: name.to_string(),
            key: SigningKey::from_keypair_bytes(&raw)?,
        })
    }

    fn sign(&self, msg: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.sign(msg).to_bytes())
    }

    fn public_key(&self) -> String {
        format_key(&self.name, &self.key.verifying_key().to_bytes())
    }
}

fn format_key(name: &str, bytes: &[u8]) -> String {
    format!(
        "{name}:{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

/// systemd's `StateDirectory=` sets `$STATE_DIRECTORY`; fall back to the working dir.
fn state_dir() -> PathBuf {
    std::env::var_os("STATE_DIRECTORY")
        .and_then(|paths| std::env::split_paths(&paths).next())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Kept under the state dir; a subdirectory so LRU eviction can't touch the key/db.
fn cache_dir() -> PathBuf {
    state_dir().join("cache")
}

fn write_secret(path: &PathBuf, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        file.write_all(contents.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[derive(Clone)]
struct App {
    whitelist: Arc<Whitelist>,
    client: reqwest::Client,
    cache: Arc<cache::Cache>,
    blobs: Arc<cache::BlobCache>,
    store_dir: StoreDir,
    signer: Arc<Signer>,
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

    let state_dir = state_dir();
    let db = args
        .db
        .clone()
        .unwrap_or_else(|| state_dir.join("substituter-api.sqlite"));
    let cache = Arc::new(cache::Cache::open(&db)?);
    let sign_key = args
        .sign_key
        .clone()
        .unwrap_or_else(|| state_dir.join("substituter-api.key"));

    let cache_dir = args.cache_dir.clone().unwrap_or_else(cache_dir);
    let blobs = Arc::new(cache::BlobCache::new(
        cache_dir.clone(),
        args.cache_max_size,
    )?);
    info!("blob cache: {}", cache_dir.display());

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
        blobs,
        store_dir: StoreDir::new(args.store_dir.clone())
            .with_context(|| format!("invalid store dir {:?}", args.store_dir))?,
        signer: Arc::new(Signer::load_or_generate(&sign_key)?),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/poke", post(poke))
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

async fn poke(State(state): State<App>, body: Bytes) -> Result<Response, ApiError> {
    let entries = parse_poke(&body)?;

    let mut records = Vec::with_capacity(entries.len());
    for (path, url) in entries {
        let basename = basename_of(&path);
        if store_hash(&basename).is_none() {
            return Err(ApiError::bad_request(format!("not a store path: {path:?}")));
        }
        let name = store_name(&basename)
            .ok_or_else(|| ApiError::bad_request(format!("not a store path: {path:?}")))?;
        resolve(&state, &url)?;
        // The store name must commit to the url, so an anonymous registration can
        // never point someone else's path at a different url.
        if name != url_committed_name(&url) {
            return Err(ApiError::forbidden(format!(
                "store name must be `{}` (sha256(url)), got {name:?}",
                url_committed_name(&url)
            )));
        }
        records.push((path, url));
    }
    for (path, url) in &records {
        info!("registered {path} -> {url}");
    }
    let cache = state.cache.clone();
    tokio::task::spawn_blocking(move || cache.record_many(&records))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
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

/// `GET /` returns the public key, to paste into `trusted-public-keys`.
async fn index(State(state): State<App>) -> Response {
    text(StatusCode::OK, &format!("{}\n", state.signer.public_key()))
}

async fn narinfo(
    method: Method,
    State(state): State<App>,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let stem = file
        .strip_suffix(".narinfo")
        .ok_or_else(|| ApiError::not_found("not found"))?;
    let (path, url) = lookup(&state, stem).await?;
    if method == Method::HEAD {
        resolve(&state, &url)?;
        return Ok(bytes(StatusCode::OK, "text/x-nix-narinfo", Bytes::new()));
    }
    let store_path = StorePath::from_basename(basename_of(&path).as_bytes())
        .map_err(|e| ApiError::internal(format!("registered path {path:?}: {e}")))?;
    let file = ensure_body(&state, &url).await?;
    let nar_hash =
        tokio::task::spawn_blocking(move || nar::hash_path(&file, nar::CaseHack::native()))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(|e| ApiError::internal(format!("nar hash: {e}")))?;

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

    let mut body = info.to_canonical_bytes();
    let fingerprint = info.fingerprint(&state.store_dir);
    body.extend_from_slice(
        format!(
            "Sig: {}:{}\n",
            state.signer.name,
            state.signer.sign(fingerprint.as_bytes())
        )
        .as_bytes(),
    );

    Ok(bytes(
        StatusCode::OK,
        "text/x-nix-narinfo",
        Bytes::from(body),
    ))
}

async fn nar_body(
    method: Method,
    State(state): State<App>,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let stem = file.strip_suffix(".nar").unwrap_or(&file);
    let (_, url) = lookup(&state, stem).await?;
    if method == Method::HEAD {
        resolve(&state, &url)?;
        return Ok(bytes(StatusCode::OK, "application/x-nix-nar", Bytes::new()));
    }
    let file = ensure_body(&state, &url).await?;
    let size = tokio::fs::metadata(&file)
        .await
        .map_err(|e| ApiError::internal(format!("cache: {e}")))?
        .len();
    let (tx, rx) = tokio::io::duplex(64 * 1024);
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut src = std::fs::File::open(&file)?;
        let mut bridge = tokio_util::io::SyncIoBridge::new(tx);
        let io = |e: nar::Error| std::io::Error::other(e.to_string());
        let mut encoder = nar::Encoder::new(&mut bridge).map_err(io)?;
        let mut regular = encoder.start_regular(None, false, size).map_err(io)?;
        std::io::copy(&mut src, &mut regular)?;
        regular.finish().map_err(io)?;
        encoder.finish().map_err(io)?;
        Ok(())
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-nix-nar")
        .body(axum::body::Body::from_stream(
            tokio_util::io::ReaderStream::new(rx),
        ))
        .expect("building response"))
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

/// Download `url` into the blob cache if not already there, and return its path.
async fn ensure_body(state: &App, url: &str) -> Result<PathBuf, ApiError> {
    let parsed = resolve(state, url)?;
    if let Some(path) = cached(state, url).await {
        return Ok(path);
    }

    // Single-flight: only the first request for a URL hits the upstream.
    let (key, lock) = state.blobs.lock(url);
    let guard = lock.clone().lock_owned().await;
    let result = match cached(state, url).await {
        Some(path) => Ok(path),
        None => fetch_into_cache(state, parsed, url).await,
    };
    drop(guard);
    state.blobs.unlock(&key, &lock);
    result
}

async fn cached(state: &App, url: &str) -> Option<PathBuf> {
    if state.blobs.exists(url).await {
        state.blobs.touch(url).await;
        Some(state.blobs.path(url))
    } else {
        None
    }
}

async fn fetch_into_cache(state: &App, parsed: Url, url: &str) -> Result<PathBuf, ApiError> {
    let mut resp = state
        .client
        .get(parsed)
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("upstream: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_gateway(format!("upstream {}", resp.status())));
    }

    let tmp = state.blobs.temp(url);
    if let Err(e) = download(&mut resp, &tmp).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }

    state
        .blobs
        .commit(url, &tmp)
        .await
        .map_err(|e| ApiError::internal(format!("cache: {e}")))?;
    Ok(state.blobs.path(url))
}

async fn download(resp: &mut reqwest::Response, tmp: &std::path::Path) -> Result<(), ApiError> {
    let mut file = tokio::fs::File::create(tmp)
        .await
        .map_err(|e| ApiError::internal(format!("cache: {e}")))?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("upstream: {e}")))?
    {
        file.write_all(&chunk)
            .await
            .map_err(|e| ApiError::internal(format!("cache: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| ApiError::internal(format!("cache: {e}")))?;
    Ok(())
}

/// A JSON array of `{"path": <store path>, "url": <url>}` entries to register.
fn parse_poke(body: &[u8]) -> Result<Vec<(String, String)>, ApiError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("expected a JSON array: {e}")))?;
    let array = value
        .as_array()
        .ok_or_else(|| ApiError::bad_request("expected a JSON array"))?;
    let mut entries = Vec::with_capacity(array.len());
    for item in array {
        let (Some(path), Some(url)) = (
            item.get("path").and_then(|x| x.as_str()),
            item.get("url").and_then(|x| x.as_str()),
        ) else {
            return Err(ApiError::bad_request(
                "each entry must be {\"path\":...,\"url\":...}",
            ));
        };
        entries.push((path.to_string(), url.to_string()));
    }
    if entries.is_empty() {
        return Err(ApiError::bad_request("no entries"));
    }
    Ok(entries)
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

/// The `<name>` of a `<hash>-<name>` store-path basename.
fn store_name(basename: &str) -> Option<&str> {
    let bytes = basename.as_bytes();
    (bytes.len() > 33 && bytes[32] == b'-' && basename.is_char_boundary(33))
        .then(|| &basename[33..])
}

/// The store name a client must use for `url`: the hex sha256 of the url.
fn url_committed_name(url: &str) -> String {
    let hex = nix_derivation::hash_bytes(nix_derivation::HashAlgorithm::Sha256, url.as_bytes())
        .to_nix_base16_string();
    hex.trim_start_matches("sha256:").to_string()
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
    fn poke_body() {
        let body = br#"[{"path":"/nix/store/x","url":"https://e.com/"}]"#;
        assert_eq!(
            parse_poke(body).unwrap(),
            vec![("/nix/store/x".to_string(), "https://e.com/".to_string())]
        );
        assert!(parse_poke(br#"{"path":"/nix/store/x","url":"https://e.com/"}"#).is_err());
        assert!(parse_poke(br#"[]"#).is_err());
    }

    #[test]
    fn committed_name() {
        let name = url_committed_name("https://example.com/");
        assert_eq!(name.len(), 64);
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(name, url_committed_name("https://example.com/"));
        assert_ne!(name, url_committed_name("https://example.com/x"));
    }

    #[test]
    fn store_name_split() {
        let h = "0123456789abcdfghijklmnpqrsvwxyz";
        assert_eq!(store_name(&format!("{h}-abc")), Some("abc"));
        assert_eq!(store_name(h), None);
    }
}
