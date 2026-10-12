use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

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
