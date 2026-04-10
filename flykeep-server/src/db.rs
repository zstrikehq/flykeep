use rusqlite::Connection;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_epoch() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| format!("system time error: {e}"))
}

pub struct SecretRow {
    pub value: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn init(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open database: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                path       TEXT PRIMARY KEY,
                value      BLOB NOT NULL,
                nonce      BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("failed to create table: {e}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_secret(&self, path: &str) -> Result<Option<SecretRow>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock poisoned: {e}"))?;
        let mut stmt = conn
            .prepare("SELECT value, nonce FROM secrets WHERE path = ?1")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let mut rows = stmt
            .query_map([path], |row| {
                Ok(SecretRow {
                    value: row.get(0)?,
                    nonce: row.get(1)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?;
        match rows.next() {
            Some(row) => Ok(Some(row.map_err(|e| format!("row read failed: {e}"))?)),
            None => Ok(None),
        }
    }

    pub fn put_secret(
        &self,
        path: &str,
        value: &[u8],
        nonce: &[u8],
    ) -> Result<(), String> {
        let now = now_epoch()?;
        let conn = self.conn.lock().map_err(|e| format!("db lock poisoned: {e}"))?;
        conn.execute(
            "INSERT INTO secrets (path, value, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(path) DO UPDATE SET
               value = excluded.value,
               nonce = excluded.nonce,
               updated_at = excluded.updated_at",
            rusqlite::params![path, value, nonce, now],
        )
        .map_err(|e| format!("insert failed: {e}"))?;
        Ok(())
    }

    pub fn list_secrets(&self, prefix: &str) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock poisoned: {e}"))?;
        let pattern = format!("{prefix}%");
        let mut stmt = conn
            .prepare("SELECT path FROM secrets WHERE path LIKE ?1")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let rows = stmt
            .query_map([&pattern], |row| row.get::<_, String>(0))
            .map_err(|e| format!("query failed: {e}"))?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(row.map_err(|e| format!("row read failed: {e}"))?);
        }
        Ok(paths)
    }

    pub fn delete_secret(&self, path: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock poisoned: {e}"))?;
        let mut stmt = conn
            .prepare("DELETE FROM secrets WHERE path = ?1 RETURNING path")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let mut rows = stmt
            .query_map([path], |row| row.get::<_, String>(0))
            .map_err(|e| format!("delete failed: {e}"))?;
        Ok(rows.next().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (Database, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("test: create temp dir");
        let db_path = dir.path().join("test.db");
        let db = Database::init(db_path.to_str().expect("test: path str"))
            .expect("test: init db");
        (db, dir)
    }

    #[test]
    fn test_init_creates_database() {
        let (_db, _dir) = temp_db();
    }

    #[test]
    fn test_put_and_get_secret() {
        let (db, _dir) = temp_db();
        let value = b"encrypted-data";
        let nonce = b"twelve_bytes";
        db.put_secret("/ns/dev/app/KEY", value, nonce).expect("test: put");
        let row = db.get_secret("/ns/dev/app/KEY").expect("test: get");
        let row = row.expect("test: should exist");
        assert_eq!(row.value, value);
        assert_eq!(row.nonce, nonce);
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let (db, _dir) = temp_db();
        let row = db.get_secret("/ns/dev/app/MISSING").expect("test: get");
        assert!(row.is_none());
    }

    #[test]
    fn test_put_upsert_preserves_created_at() {
        let (db, _dir) = temp_db();
        db.put_secret("/ns/dev/app/KEY", b"v1", b"nonce_1_12by")
            .expect("test: put v1");

        let conn = db.conn.lock().expect("test: lock");
        let created: i64 = conn
            .query_row(
                "SELECT created_at FROM secrets WHERE path = ?1",
                ["/ns/dev/app/KEY"],
                |row| row.get(0),
            )
            .expect("test: query created_at");
        drop(conn);

        std::thread::sleep(std::time::Duration::from_secs(1));

        db.put_secret("/ns/dev/app/KEY", b"v2", b"nonce_2_12by")
            .expect("test: put v2");

        let conn = db.conn.lock().expect("test: lock");
        let created_after: i64 = conn
            .query_row(
                "SELECT created_at FROM secrets WHERE path = ?1",
                ["/ns/dev/app/KEY"],
                |row| row.get(0),
            )
            .expect("test: query created_at after");
        let updated_after: i64 = conn
            .query_row(
                "SELECT updated_at FROM secrets WHERE path = ?1",
                ["/ns/dev/app/KEY"],
                |row| row.get(0),
            )
            .expect("test: query updated_at after");
        drop(conn);

        assert_eq!(created, created_after, "created_at must not change on update");
        assert!(updated_after >= created, "updated_at must advance");
    }

    #[test]
    fn test_list_secrets_by_prefix() {
        let (db, _dir) = temp_db();
        db.put_secret("/ns/dev/app/A", b"v", b"nonce_a_12by").expect("test: put A");
        db.put_secret("/ns/dev/app/B", b"v", b"nonce_b_12by").expect("test: put B");
        db.put_secret("/ns/prod/app/C", b"v", b"nonce_c_12by").expect("test: put C");

        let paths = db.list_secrets("/ns/dev/").expect("test: list");
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/ns/dev/app/A".to_string()));
        assert!(paths.contains(&"/ns/dev/app/B".to_string()));
    }

    #[test]
    fn test_list_secrets_no_matches() {
        let (db, _dir) = temp_db();
        let paths = db.list_secrets("/nothing/").expect("test: list");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_delete_existing_returns_true() {
        let (db, _dir) = temp_db();
        db.put_secret("/ns/dev/app/KEY", b"v", b"nonce_x_12by").expect("test: put");
        let deleted = db.delete_secret("/ns/dev/app/KEY").expect("test: delete");
        assert!(deleted);
        let row = db.get_secret("/ns/dev/app/KEY").expect("test: get after delete");
        assert!(row.is_none());
    }

    #[test]
    fn test_delete_nonexistent_returns_false() {
        let (db, _dir) = temp_db();
        let deleted = db.delete_secret("/ns/dev/app/MISSING").expect("test: delete");
        assert!(!deleted);
    }
}
