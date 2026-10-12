use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use nix_derivation::{HashAlgorithm, hash_bytes};
use rusqlite::{Connection, OptionalExtension, params};

/// On-disk cache of fetched bodies, keyed by URL, evicted LRU when over budget.
pub struct BlobCache {
    dir: PathBuf,
    max_size: u64,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl BlobCache {
    pub fn new(dir: PathBuf, max_size: u64) -> Result<Self> {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating cache dir {}", dir.display()))?;
        Ok(BlobCache {
            dir,
            max_size,
            locks: Mutex::new(HashMap::new()),
        })
    }

    fn key(url: &str) -> String {
        hash_bytes(HashAlgorithm::Sha256, url.as_bytes())
            .to_nix_base16_string()
            .trim_start_matches("sha256:")
            .to_string()
    }

    pub fn path(&self, url: &str) -> PathBuf {
        self.dir.join(Self::key(url))
    }

    /// A unique path to stream a download into before committing it.
    pub fn temp(&self, url: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!(
            "{}.{}.{}.tmp",
            Self::key(url),
            std::process::id(),
            seq
        ))
    }

    pub async fn exists(&self, url: &str) -> bool {
        tokio::fs::metadata(self.path(url))
            .await
            .is_ok_and(|meta| meta.is_file())
    }

    /// Bump mtime so eviction is least-recently-used.
    pub async fn touch(&self, url: &str) {
        if let Ok(file) = tokio::fs::OpenOptions::new()
            .write(true)
            .open(self.path(url))
            .await
        {
            let _ = file.into_std().await.set_modified(SystemTime::now());
        }
    }

    /// Move a finished download into place, then evict to fit the budget.
    pub async fn commit(&self, url: &str, tmp: &Path) -> std::io::Result<()> {
        let dst = self.path(url);
        tokio::fs::rename(tmp, &dst).await?;
        let dir = self.dir.clone();
        let max = self.max_size;
        let _ = tokio::task::spawn_blocking(move || evict(&dir, max, &dst)).await;
        Ok(())
    }

    /// Single-flight: one download per URL at a time.
    pub fn lock(&self, url: &str) -> (String, Arc<tokio::sync::Mutex<()>>) {
        let key = Self::key(url);
        let mut locks = self.locks.lock().expect("blob cache locks");
        let lock = locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        (key, lock)
    }

    /// Release the single-flight slot held by [`Self::lock`].
    pub fn unlock(&self, key: &str, lock: &Arc<tokio::sync::Mutex<()>>) {
        let mut locks = self.locks.lock().expect("blob cache locks");
        if locks
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, lock))
        {
            locks.remove(key);
        }
    }
}

#[cfg(test)]
mod streaming_tests {
    use nix_archive::nar;

    /// Concurrent downloads of the same URL must not share a temp path.
    #[test]
    fn temp_paths_are_unique() {
        let dir = std::env::temp_dir().join(format!("substituter-api-tmp-{}", std::process::id()));
        let cache = super::BlobCache::new(dir.clone(), 0).unwrap();
        assert_ne!(
            cache.temp("https://example.com/"),
            cache.temp("https://example.com/")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The incremental encoder produces the same NAR bytes as `encode_regular`.
    #[test]
    fn streaming_encoder_matches_encode_regular() {
        for data in [&b""[..], &b"hi"[..], &b"12345678"[..], &b"123456789"[..]] {
            let mut expected = Vec::new();
            nar::encode_regular(&mut expected, data, false).unwrap();

            let mut got = Vec::new();
            let mut encoder = nar::Encoder::new(&mut got).unwrap();
            let mut file = encoder
                .start_regular(None, false, data.len() as u64)
                .unwrap();
            std::io::Write::write_all(&mut file, data).unwrap();
            file.finish().unwrap();
            encoder.finish().unwrap();

            assert_eq!(got, expected);
        }
    }
}

/// Delete least-recently-used entries until the cache fits in `max` bytes,
/// always keeping `keep` (the entry just written).
fn evict(dir: &Path, max: u64, keep: &Path) -> std::io::Result<()> {
    let mut total = 0u64;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        total += meta.len();
        let path = entry.path();
        if path != keep {
            entries.push((
                meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                meta.len(),
                path,
            ));
        }
    }
    entries.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in entries {
        if total <= max {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total -= size;
        }
    }
    Ok(())
}

pub struct Cache {
    conn: Mutex<Connection>,
}

impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite db {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS paths (
                 path TEXT PRIMARY KEY,
                 url  TEXT NOT NULL
             );",
        )
        .context("initializing schema")?;
        Ok(Cache {
            conn: Mutex::new(conn),
        })
    }

    pub fn record(&self, path: &str, url: &str) -> Result<()> {
        let conn = self.conn.lock().expect("cache mutex");
        conn.execute(
            "INSERT INTO paths (path, url) VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET url = excluded.url",
            params![path, url],
        )?;
        Ok(())
    }

    /// Look up by the 32-char hash; `path` is `<store_dir>/<hash>-<name>`, so a
    /// prefix range hits the primary-key index.
    pub fn lookup(&self, store_dir: &str, hash: &str) -> Result<Option<(String, String)>> {
        let low = format!("{store_dir}/{hash}-");
        let high = format!("{store_dir}/{hash}.");
        let conn = self.conn.lock().expect("cache mutex");
        Ok(conn
            .query_row(
                "SELECT path, url FROM paths WHERE path >= ?1 AND path < ?2 LIMIT 1",
                params![low, high],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_lookup() {
        let dir = std::env::temp_dir().join(format!("substituter-api-test-{}", std::process::id()));
        let cache = Cache::open(&dir.join("cache.sqlite")).unwrap();
        cache.record("/nix/store/abc-x", "https://e.com/").unwrap();
        assert_eq!(
            cache.lookup("/nix/store", "abc").unwrap().unwrap().1,
            "https://e.com/"
        );
        assert!(cache.lookup("/nix/store", "nope").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
