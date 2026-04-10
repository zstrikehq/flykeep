# flykeep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two independent Rust binaries — a secret store HTTP server and a CLI client.

**Architecture:** Server uses Salvo for HTTP, rusqlite for storage, aes-gcm for encryption. CLI uses clap for argument parsing, reqwest for HTTP, comfy-table for output. Two independent Cargo projects, thin module split per project.

**Tech Stack:** Rust, Salvo, rusqlite (bundled), aes-gcm, clap, reqwest, comfy-table, tokio

**Coding Constraints:** No `unwrap()`. No `unsafe`. Use `?` operator, `expect()` only at startup, or explicit `match`/`if let`.

---

## File Structure

### flykeep-server

```
flykeep-server/
  src/
    main.rs        -- startup, config, router wiring
    auth.rs        -- auth decision logic + Salvo middleware
    crypto.rs      -- AES-256-GCM encrypt/decrypt
    db.rs          -- SQLite init + CRUD
    routes.rs      -- path validation + HTTP handlers
  Cargo.toml
  Dockerfile
  fly.toml
```

### flykeep-cli

```
flykeep-cli/
  src/
    main.rs        -- clap commands, output formatting, dispatch
    config.rs      -- env var + TOML config loading
    client.rs      -- reqwest HTTP client wrapper
  Cargo.toml
```

---

### Task 1: Server project scaffolding

**Files:**
- Create: `flykeep-server/Cargo.toml`
- Create: `flykeep-server/src/main.rs`
- Create: `flykeep-server/src/crypto.rs`
- Create: `flykeep-server/src/db.rs`
- Create: `flykeep-server/src/auth.rs`
- Create: `flykeep-server/src/routes.rs`

- [ ] **Step 1: Initialize the Cargo project**

Run: `cargo init flykeep-server`

- [ ] **Step 2: Set up Cargo.toml with all dependencies**

Replace `flykeep-server/Cargo.toml` with:

```toml
[package]
name = "flykeep-server"
version = "0.1.0"
edition = "2021"

[dependencies]
salvo = { version = "0.77", features = ["json"] }
tokio = { version = "1", features = ["full"] }
rusqlite = { version = "0.32", features = ["bundled"] }
aes-gcm = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
dotenvy = "0.15"
hex = "0.4"
rand = "0.8"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Create empty module files**

Create `flykeep-server/src/crypto.rs`:
```rust
```

Create `flykeep-server/src/db.rs`:
```rust
```

Create `flykeep-server/src/auth.rs`:
```rust
```

Create `flykeep-server/src/routes.rs`:
```rust
```

- [ ] **Step 4: Set up main.rs with module declarations**

Replace `flykeep-server/src/main.rs` with:

```rust
mod auth;
mod crypto;
mod db;
mod routes;

fn main() {
    println!("flykeep-server");
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cd flykeep-server && cargo check`
Expected: compiles with no errors (warnings about unused modules are fine)

- [ ] **Step 6: Commit**

```bash
git add flykeep-server/
git commit -m "feat: scaffold flykeep-server project with dependencies"
```

---

### Task 2: Encryption module (TDD)

**Files:**
- Modify: `flykeep-server/src/crypto.rs`

- [ ] **Step 1: Write failing tests**

Write `flykeep-server/src/crypto.rs`:

```rust
pub fn encrypt(_key: &[u8; 32], _plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    todo!()
}

pub fn decrypt(_key: &[u8; 32], _ciphertext: &[u8], _nonce: &[u8]) -> Result<String, String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "my-secret-value";
        let (ciphertext, nonce) = encrypt(&key, plaintext).expect("test: encrypt");
        let result = decrypt(&key, &ciphertext, &nonce).expect("test: decrypt");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_encrypt_produces_unique_output() {
        let key = test_key();
        let plaintext = "same-value";
        let (ct1, nonce1) = encrypt(&key, plaintext).expect("test: encrypt 1");
        let (ct2, nonce2) = encrypt(&key, plaintext).expect("test: encrypt 2");
        assert_ne!(nonce1, nonce2, "nonces must differ");
        assert_ne!(ct1, ct2, "ciphertexts must differ");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = test_key();
        let wrong_key = [0xCD; 32];
        let (ciphertext, nonce) = encrypt(&key, "secret").expect("test: encrypt");
        let result = decrypt(&wrong_key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = test_key();
        let (ciphertext, _nonce) = encrypt(&key, "secret").expect("test: encrypt");
        let wrong_nonce = vec![0u8; 12];
        let result = decrypt(&key, &ciphertext, &wrong_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_string() {
        let key = test_key();
        let (ciphertext, nonce) = encrypt(&key, "").expect("test: encrypt empty");
        let result = decrypt(&key, &ciphertext, &nonce).expect("test: decrypt empty");
        assert_eq!(result, "");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-server && cargo test --lib crypto`
Expected: all 5 tests panic with `not yet implemented`

- [ ] **Step 3: Implement encrypt and decrypt**

Replace the `encrypt` and `decrypt` function bodies in `flykeep-server/src/crypto.rs`:

```rust
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))?;
    String::from_utf8(plaintext_bytes).map_err(|e| format!("invalid utf-8: {e}"))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd flykeep-server && cargo test --lib crypto`
Expected: all 5 tests pass

- [ ] **Step 5: Commit**

```bash
cd flykeep-server && git add -A && git commit -m "feat: implement AES-256-GCM encrypt/decrypt with tests"
```

---

### Task 3: Database module (TDD)

**Files:**
- Modify: `flykeep-server/src/db.rs`

- [ ] **Step 1: Write failing tests**

Write `flykeep-server/src/db.rs`:

```rust
pub struct SecretRow {
    pub value: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct Database {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl Database {
    pub fn init(_path: &str) -> Result<Self, String> {
        todo!()
    }

    pub fn get_secret(&self, _path: &str) -> Result<Option<SecretRow>, String> {
        todo!()
    }

    pub fn put_secret(
        &self,
        _path: &str,
        _value: &[u8],
        _nonce: &[u8],
    ) -> Result<(), String> {
        todo!()
    }

    pub fn list_secrets(&self, _prefix: &str) -> Result<Vec<String>, String> {
        todo!()
    }

    pub fn delete_secret(&self, _path: &str) -> Result<bool, String> {
        todo!()
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

        // Read created_at
        let conn = db.conn.lock().expect("test: lock");
        let created: i64 = conn
            .query_row(
                "SELECT created_at FROM secrets WHERE path = ?1",
                ["/ns/dev/app/KEY"],
                |row| row.get(0),
            )
            .expect("test: query created_at");
        drop(conn);

        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Update
        db.put_secret("/ns/dev/app/KEY", b"v2", b"nonce_2_12by")
            .expect("test: put v2");

        // created_at should be unchanged
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-server && cargo test --lib db`
Expected: all 7 tests panic with `not yet implemented`

- [ ] **Step 3: Implement Database::init**

Replace the `init` body:

```rust
use rusqlite::Connection;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

fn now_epoch() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| format!("system time error: {e}"))
}
```

- [ ] **Step 4: Implement get_secret**

```rust
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
```

- [ ] **Step 5: Implement put_secret**

```rust
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
```

- [ ] **Step 6: Implement list_secrets**

```rust
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
```

- [ ] **Step 7: Implement delete_secret**

```rust
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
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd flykeep-server && cargo test --lib db`
Expected: all 7 tests pass

- [ ] **Step 9: Commit**

```bash
cd flykeep-server && git add -A && git commit -m "feat: implement SQLite database layer with CRUD operations"
```

---

### Task 4: Auth module (TDD)

**Files:**
- Modify: `flykeep-server/src/auth.rs`

- [ ] **Step 1: Write failing tests**

Write `flykeep-server/src/auth.rs`:

```rust
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthLevel {
    Admin,
    NetworkRead,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
}

pub fn check_auth(
    _auth_header: Option<&str>,
    _remote_ip: Option<&IpAddr>,
    _admin_token: &str,
) -> Result<AuthLevel, AuthError> {
    todo!()
}

pub fn is_fly_private_network(_ip: &IpAddr) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_admin_token() {
        let result = check_auth(Some("Bearer my-token"), None, "my-token");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_invalid_admin_token() {
        let result = check_auth(Some("Bearer wrong-token"), None, "my-token");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_malformed_auth_header() {
        let result = check_auth(Some("Basic abc123"), None, "my-token");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_no_token_fly_private_ipv6() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Ok(AuthLevel::NetworkRead));
    }

    #[test]
    fn test_no_token_public_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_no_token_ipv4() {
        let ip: IpAddr = "192.168.1.1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_no_token_no_ip() {
        let result = check_auth(None, None, "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_admin_token_overrides_private_network() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        let result = check_auth(Some("Bearer my-token"), Some(&ip), "my-token");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_is_fly_private_fdaa() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        assert!(is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_fly_private_fd_range() {
        let ip: IpAddr = "fd00::1".parse().expect("test: parse ip");
        assert!(is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_not_fly_private_public_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().expect("test: parse ip");
        assert!(!is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_not_fly_private_ipv4() {
        let ip: IpAddr = "10.0.0.1".parse().expect("test: parse ip");
        assert!(!is_fly_private_network(&ip));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-server && cargo test --lib auth`
Expected: all 12 tests panic with `not yet implemented`

- [ ] **Step 3: Implement is_fly_private_network**

Replace the `is_fly_private_network` body:

```rust
pub fn is_fly_private_network(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            // fdaa::/8 — first 8 bits are 0xFD
            (v6.segments()[0] >> 8) == 0xFD
        }
        _ => false,
    }
}
```

- [ ] **Step 4: Implement check_auth**

Replace the `check_auth` body:

```rust
pub fn check_auth(
    auth_header: Option<&str>,
    remote_ip: Option<&IpAddr>,
    admin_token: &str,
) -> Result<AuthLevel, AuthError> {
    // Check token first
    if let Some(header) = auth_header {
        let token = header.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
        if token == admin_token {
            return Ok(AuthLevel::Admin);
        }
        return Err(AuthError::Unauthorized);
    }

    // No token — check network
    if let Some(ip) = remote_ip {
        if is_fly_private_network(ip) {
            return Ok(AuthLevel::NetworkRead);
        }
    }

    Err(AuthError::Forbidden)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd flykeep-server && cargo test --lib auth`
Expected: all 12 tests pass

- [ ] **Step 6: Commit**

```bash
cd flykeep-server && git add -A && git commit -m "feat: implement auth logic with token and private network checks"
```

---

### Task 5: Routes + path validation (TDD)

**Files:**
- Modify: `flykeep-server/src/routes.rs`

- [ ] **Step 1: Write path validation tests**

Write `flykeep-server/src/routes.rs`:

```rust
pub fn validate_path(path: &str) -> Result<(), String> {
    todo!()
}

pub fn validate_prefix(prefix: &str) -> Result<(), String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_path_two_segments() {
        assert!(validate_path("/ns/KEY").is_ok());
    }

    #[test]
    fn test_valid_path_four_segments() {
        assert!(validate_path("/ns/dev/app/KEY").is_ok());
    }

    #[test]
    fn test_path_no_leading_slash() {
        assert!(validate_path("ns/dev/app/KEY").is_err());
    }

    #[test]
    fn test_path_trailing_slash() {
        assert!(validate_path("/ns/dev/app/KEY/").is_err());
    }

    #[test]
    fn test_path_single_segment() {
        assert!(validate_path("/KEY").is_err());
    }

    #[test]
    fn test_path_empty() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn test_path_just_slash() {
        assert!(validate_path("/").is_err());
    }

    #[test]
    fn test_valid_prefix() {
        assert!(validate_prefix("/ns/dev/").is_ok());
    }

    #[test]
    fn test_prefix_no_trailing_slash() {
        assert!(validate_prefix("/ns/dev").is_err());
    }

    #[test]
    fn test_prefix_no_leading_slash() {
        assert!(validate_prefix("ns/dev/").is_err());
    }

    #[test]
    fn test_prefix_just_slash() {
        assert!(validate_prefix("/").is_ok());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-server && cargo test --lib routes`
Expected: all 11 tests panic with `not yet implemented`

- [ ] **Step 3: Implement path validation**

Replace the `validate_path` and `validate_prefix` bodies:

```rust
pub fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("path must start with /".to_string());
    }
    if path.ends_with('/') {
        return Err("path must not end with /".to_string());
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.len() < 2 {
        return Err("path must have at least 2 segments".to_string());
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err("path must not contain empty segments".to_string());
    }
    Ok(())
}

pub fn validate_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("prefix must start with /".to_string());
    }
    if !prefix.ends_with('/') {
        return Err("prefix must end with /".to_string());
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd flykeep-server && cargo test --lib routes`
Expected: all 11 tests pass

- [ ] **Step 5: Commit**

```bash
cd flykeep-server && git add -A && git commit -m "feat: implement path and prefix validation with tests"
```

---

### Task 6: Server main.rs wiring + route handlers

**Files:**
- Modify: `flykeep-server/src/main.rs`
- Modify: `flykeep-server/src/routes.rs`
- Modify: `flykeep-server/src/auth.rs`

This task wires everything together: AppState, Salvo middleware, route handlers, and startup.

- [ ] **Step 1: Define AppState and config loading in main.rs**

Replace `flykeep-server/src/main.rs`:

```rust
mod auth;
mod crypto;
mod db;
mod routes;

use db::Database;
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Database>,
    pub encryption_key: [u8; 32],
    pub admin_token: String,
}

fn load_config() -> Result<(String, String, String, u16), String> {
    let _ = dotenvy::dotenv();
    let encryption_key_hex = std::env::var("FLYKEEP_ENCRYPTION_KEY")
        .map_err(|_| "FLYKEEP_ENCRYPTION_KEY is required".to_string())?;
    let admin_token = std::env::var("FLYKEEP_ADMIN_TOKEN")
        .map_err(|_| "FLYKEEP_ADMIN_TOKEN is required".to_string())?;
    let db_path = std::env::var("FLYKEEP_DB_PATH").unwrap_or_else(|_| "./vault.db".to_string());
    let port: u16 = std::env::var("FLYKEEP_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .map_err(|e| format!("invalid FLYKEEP_PORT: {e}"))?;
    Ok((encryption_key_hex, admin_token, db_path, port))
}

fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid FLYKEEP_ENCRYPTION_KEY hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "FLYKEEP_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[tokio::main]
async fn main() {
    let (encryption_key_hex, admin_token, db_path, port) = load_config()
        .expect("startup: failed to load config");

    let encryption_key = parse_encryption_key(&encryption_key_hex)
        .expect("startup: failed to parse encryption key");

    let database = Database::init(&db_path).expect("startup: failed to initialize database");

    let state = Arc::new(AppState {
        db: Arc::new(database),
        encryption_key,
        admin_token,
    });

    let router = routes::create_router(state);

    let bind_addr = format!("0.0.0.0:{port}");
    eprintln!("flykeep-server listening on {bind_addr}");
    let acceptor = salvo::conn::TcpListener::new(&bind_addr)
        .bind()
        .await;
    salvo::Server::new(acceptor).serve(router).await;
}
```

Note: `load_config` uses `unwrap_or_else` for optional vars with defaults. This is not `unwrap()` — it's providing a default value. `expect()` is used at startup only, as allowed by constraints.

- [ ] **Step 2: Add Salvo auth middleware to auth.rs**

Append to `flykeep-server/src/auth.rs` (keep all existing code):

```rust
use salvo::prelude::*;
use salvo::http::StatusCode;
use std::sync::Arc;

pub struct AuthMiddleware {
    pub state: Arc<crate::AppState>,
}

#[handler]
impl AuthMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let remote_ip = req.remote_addr()
            .and_then(|addr| {
                match addr {
                    salvo::conn::addr::SocketAddr::IPv6(v6) => Some(IpAddr::V6(*v6.ip())),
                    salvo::conn::addr::SocketAddr::IPv4(v4) => Some(IpAddr::V4(*v4.ip())),
                    _ => None,
                }
            });

        match check_auth(auth_header, remote_ip.as_ref(), &self.state.admin_token) {
            Ok(level) => {
                depot.inject(level);
                depot.inject(self.state.clone());
                ctrl.call_next(req, depot, res).await;
            }
            Err(AuthError::Unauthorized) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(salvo::writing::Json(serde_json::json!({"error": "unauthorized"})));
            }
            Err(AuthError::Forbidden) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(salvo::writing::Json(serde_json::json!({"error": "forbidden"})));
            }
        }
    }
}
```

Note: The exact `remote_addr()` API depends on the Salvo version. If `salvo::conn::addr::SocketAddr` doesn't exist, adapt to use `req.remote_addr().as_ipv6()` or `req.remote_addr().as_ipv4()` depending on the available API. Check Salvo docs for the installed version.

- [ ] **Step 3: Implement route handlers in routes.rs**

Append to `flykeep-server/src/routes.rs` (keep existing validation code and tests):

```rust
use crate::auth::{AuthLevel, AuthMiddleware};
use crate::crypto;
use crate::AppState;
use salvo::prelude::*;
use salvo::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub fn create_router(state: Arc<AppState>) -> Router {
    let auth = AuthMiddleware { state };
    Router::new().hoop(auth).push(
        Router::with_path("secrets")
            .get(get_secrets)
            .put(put_secret)
            .delete(delete_secret),
    )
}

fn json_error(res: &mut Response, status: StatusCode, message: &str) {
    res.status_code(status);
    res.render(salvo::writing::Json(json!({"error": message})));
}

#[handler]
async fn get_secrets(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.try_obtain::<Arc<AppState>>() {
        Some(s) => s.clone(),
        None => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };

    // Check if this is a single-path read or a prefix list
    if let Some(path) = req.query::<String>("path") {
        get_single_secret(&state, &path, res).await;
    } else if let Some(prefix) = req.query::<String>("prefix") {
        list_secrets(&state, &prefix, res).await;
    } else {
        json_error(res, StatusCode::BAD_REQUEST, "missing path or prefix parameter");
    }
}

async fn get_single_secret(state: &Arc<AppState>, path: &str, res: &mut Response) {
    if let Err(e) = validate_path(path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }

    let db = state.db.clone();
    let key = state.encryption_key;
    let path_owned = path.to_string();

    let result = tokio::task::spawn_blocking(move || db.get_secret(&path_owned))
        .await;

    match result {
        Ok(Ok(Some(row))) => {
            match crypto::decrypt(&key, &row.value, &row.nonce) {
                Ok(plaintext) => {
                    res.render(salvo::writing::Json(json!({
                        "path": path,
                        "value": plaintext
                    })));
                }
                Err(e) => {
                    json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("decryption error: {e}"));
                }
            }
        }
        Ok(Ok(None)) => {
            json_error(res, StatusCode::NOT_FOUND, "not found");
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

async fn list_secrets(state: &Arc<AppState>, prefix: &str, res: &mut Response) {
    if let Err(e) = validate_prefix(prefix) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }

    let db = state.db.clone();
    let prefix_owned = prefix.to_string();

    let result = tokio::task::spawn_blocking(move || db.list_secrets(&prefix_owned))
        .await;

    match result {
        Ok(Ok(paths)) => {
            res.render(salvo::writing::Json(json!({"paths": paths})));
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

#[derive(Deserialize)]
struct PutSecretBody {
    path: String,
    value: String,
}

#[handler]
async fn put_secret(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // Check auth level — must be Admin for writes
    let auth_level = match depot.try_obtain::<AuthLevel>() {
        Some(level) => level.clone(),
        None => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    if auth_level != AuthLevel::Admin {
        json_error(res, StatusCode::FORBIDDEN, "write operations require admin token");
        return;
    }

    let state = match depot.try_obtain::<Arc<AppState>>() {
        Some(s) => s.clone(),
        None => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };

    let body: PutSecretBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            json_error(res, StatusCode::BAD_REQUEST, &format!("invalid body: {e}"));
            return;
        }
    };

    if let Err(e) = validate_path(&body.path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }

    let key = state.encryption_key;
    let (ciphertext, nonce) = match crypto::encrypt(&key, &body.value) {
        Ok(result) => result,
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("encryption error: {e}"));
            return;
        }
    };

    let db = state.db.clone();
    let path = body.path.clone();
    let result = tokio::task::spawn_blocking(move || db.put_secret(&path, &ciphertext, &nonce))
        .await;

    match result {
        Ok(Ok(())) => {
            res.render(salvo::writing::Json(json!({"ok": true})));
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

#[handler]
async fn delete_secret(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // Check auth level — must be Admin for writes
    let auth_level = match depot.try_obtain::<AuthLevel>() {
        Some(level) => level.clone(),
        None => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    if auth_level != AuthLevel::Admin {
        json_error(res, StatusCode::FORBIDDEN, "write operations require admin token");
        return;
    }

    let state = match depot.try_obtain::<Arc<AppState>>() {
        Some(s) => s.clone(),
        None => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };

    let path = match req.query::<String>("path") {
        Some(p) => p,
        None => {
            json_error(res, StatusCode::BAD_REQUEST, "missing path parameter");
            return;
        }
    };

    if let Err(e) = validate_path(&path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }

    let db = state.db.clone();
    let path_clone = path.clone();
    let result = tokio::task::spawn_blocking(move || db.delete_secret(&path_clone))
        .await;

    match result {
        Ok(Ok(true)) => {
            res.render(salvo::writing::Json(json!({"ok": true})));
        }
        Ok(Ok(false)) => {
            json_error(res, StatusCode::NOT_FOUND, "not found");
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cd flykeep-server && cargo check`
Expected: compiles with no errors

Note: The exact Salvo API (especially `remote_addr()`, `depot.inject()`, `depot.try_obtain()`, `req.parse_json()`) may vary by version. If compilation fails on a specific Salvo API call, check the Salvo docs for the installed version and adapt. The logic and structure remain the same.

- [ ] **Step 5: Add integration tests to routes.rs**

Append to the `#[cfg(test)] mod tests` block in `flykeep-server/src/routes.rs`:

```rust
    use crate::db::Database;
    use crate::AppState;
    use salvo::test::TestClient;
    use salvo::Service;
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    fn test_token() -> String {
        "test-admin-token".to_string()
    }

    fn setup_service() -> (Service, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("test: create temp dir");
        let db_path = dir.path().join("test.db");
        let db = Database::init(db_path.to_str().expect("test: path"))
            .expect("test: init db");
        let state = Arc::new(AppState {
            db: Arc::new(db),
            encryption_key: test_key(),
            admin_token: test_token(),
        });
        let router = super::create_router(state);
        (Service::new(router), dir)
    }

    fn auth_header() -> String {
        format!("Bearer {}", test_token())
    }

    #[tokio::test]
    async fn test_put_and_get_roundtrip() {
        let (service, _dir) = setup_service();

        // PUT
        let res = TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", &auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/DB_URL", "value": "postgres://localhost"}))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);

        // GET
        let mut res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/DB_URL")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
        let body: Value = res.take_json().await.expect("test: parse json");
        assert_eq!(body["path"], "/ns/dev/app/DB_URL");
        assert_eq!(body["value"], "postgres://localhost");
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_404() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/MISSING")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let (service, _dir) = setup_service();

        // Put two secrets
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", &auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/A", "value": "val-a"}))
            .send(&service)
            .await;
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", &auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/B", "value": "val-b"}))
            .send(&service)
            .await;

        // List
        let mut res = TestClient::get("http://127.0.0.1:5800/secrets?prefix=/ns/dev/")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
        let body: Value = res.take_json().await.expect("test: parse json");
        let paths = body["paths"].as_array().expect("test: paths array");
        assert_eq!(paths.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_existing() {
        let (service, _dir) = setup_service();

        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", &auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/KEY", "value": "val"}))
            .send(&service)
            .await;

        let res = TestClient::delete("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_returns_404() {
        let (service, _dir) = setup_service();
        let res = TestClient::delete("http://127.0.0.1:5800/secrets?path=/ns/dev/app/NOPE")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_invalid_path_returns_400() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=no-slash")
            .add_header("authorization", &auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_no_auth_from_public_ip_returns_403() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .send(&service)
            .await;
        // TestClient connects from 127.0.0.1 (IPv4), which is not in fdaa::/8
        assert_eq!(res.status_code.expect("test: status"), StatusCode::FORBIDDEN);
    }
}
```

- [ ] **Step 6: Run all server tests**

Run: `cd flykeep-server && cargo test`
Expected: all tests pass (crypto: 5, db: 7, auth: 12, routes: 18)

Note: If any Salvo test APIs differ from what's shown, adapt the test code. The test logic (what to assert) remains the same.

- [ ] **Step 7: Commit**

```bash
cd flykeep-server && git add -A && git commit -m "feat: implement route handlers, auth middleware, and wiring"
```

---

### Task 7: CLI project scaffolding

**Files:**
- Create: `flykeep-cli/Cargo.toml`
- Create: `flykeep-cli/src/main.rs`
- Create: `flykeep-cli/src/config.rs`
- Create: `flykeep-cli/src/client.rs`

- [ ] **Step 1: Initialize the Cargo project**

Run: `cargo init flykeep-cli`

- [ ] **Step 2: Set up Cargo.toml**

Replace `flykeep-cli/Cargo.toml`:

```toml
[package]
name = "flykeep-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = { version = "0.12", features = ["rustls-tls", "json"], default-features = false }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
comfy-table = "7"
dotenvy = "0.15"

[dev-dependencies]
wiremock = "0.6"
tempfile = "3"
```

- [ ] **Step 3: Create empty module files**

Create `flykeep-cli/src/config.rs`:
```rust
```

Create `flykeep-cli/src/client.rs`:
```rust
```

- [ ] **Step 4: Set up main.rs**

Replace `flykeep-cli/src/main.rs`:

```rust
mod client;
mod config;

fn main() {
    println!("flykeep-cli");
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cd flykeep-cli && cargo check`
Expected: compiles with no errors

- [ ] **Step 6: Commit**

```bash
git add flykeep-cli/ && git commit -m "feat: scaffold flykeep-cli project with dependencies"
```

---

### Task 8: CLI config module (TDD)

**Files:**
- Modify: `flykeep-cli/src/config.rs`

- [ ] **Step 1: Write failing tests**

Write `flykeep-cli/src/config.rs`:

```rust
pub struct Config {
    pub server_url: String,
    pub admin_token: String,
}

pub fn load_config() -> Result<Config, String> {
    todo!()
}

fn config_file_path() -> Option<std::path::PathBuf> {
    todo!()
}

fn load_from_file(path: &std::path::Path) -> Result<Config, String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_config_from_env_vars() {
        // Temporarily set env vars
        std::env::set_var("FLYKEEP_SERVER_URL", "http://test:8080");
        std::env::set_var("FLYKEEP_ADMIN_TOKEN", "test-token");
        let config = load_config().expect("test: load config");
        assert_eq!(config.server_url, "http://test:8080");
        assert_eq!(config.admin_token, "test-token");
        std::env::remove_var("FLYKEEP_SERVER_URL");
        std::env::remove_var("FLYKEEP_ADMIN_TOKEN");
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(
            b"server_url = \"http://file:8080\"\nadmin_token = \"file-token\"\n",
        )
        .expect("test: write file");

        let config = load_from_file(&file_path).expect("test: load from file");
        assert_eq!(config.server_url, "http://file:8080");
        assert_eq!(config.admin_token, "file-token");
    }

    #[test]
    fn test_load_from_file_missing_fields() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(b"server_url = \"http://file:8080\"\n")
            .expect("test: write file");

        let result = load_from_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_path_returns_some() {
        let path = config_file_path();
        if let Some(p) = path {
            assert!(p.ends_with("flykeep/config.toml"));
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-cli && cargo test --lib config`
Expected: all 4 tests panic with `not yet implemented`

- [ ] **Step 3: Implement config loading**

Replace the function bodies in `flykeep-cli/src/config.rs`:

```rust
use serde::Deserialize;
use std::path::PathBuf;

pub struct Config {
    pub server_url: String,
    pub admin_token: String,
}

#[derive(Deserialize)]
struct FileConfig {
    server_url: Option<String>,
    admin_token: Option<String>,
}

pub fn load_config() -> Result<Config, String> {
    let _ = dotenvy::dotenv();

    let env_url = std::env::var("FLYKEEP_SERVER_URL").ok();
    let env_token = std::env::var("FLYKEEP_ADMIN_TOKEN").ok();

    // If both env vars present, use them
    if let (Some(url), Some(token)) = (&env_url, &env_token) {
        return Ok(Config {
            server_url: url.clone(),
            admin_token: token.clone(),
        });
    }

    // Try loading from file and merge with env vars
    let file_config = config_file_path()
        .and_then(|p| {
            if p.exists() {
                load_from_file(&p).ok()
            } else {
                None
            }
        });

    let server_url = env_url
        .or_else(|| file_config.as_ref().map(|c| c.server_url.clone()))
        .ok_or("FLYKEEP_SERVER_URL not set and no config file found")?;

    let admin_token = env_token
        .or_else(|| file_config.as_ref().map(|c| c.admin_token.clone()))
        .ok_or("FLYKEEP_ADMIN_TOKEN not set and no config file found")?;

    Ok(Config {
        server_url,
        admin_token,
    })
}

fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".config").join("flykeep").join("config.toml"))
}

fn load_from_file(path: &std::path::Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file: {e}"))?;
    let file_config: FileConfig = toml::from_str(&content)
        .map_err(|e| format!("failed to parse config file: {e}"))?;
    let server_url = file_config
        .server_url
        .ok_or("server_url missing in config file")?;
    let admin_token = file_config
        .admin_token
        .ok_or("admin_token missing in config file")?;
    Ok(Config {
        server_url,
        admin_token,
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd flykeep-cli && cargo test --lib config`
Expected: all 4 tests pass

Note: The env var test (`test_config_from_env_vars`) may interfere with other tests if run in parallel. Rust runs tests in parallel by default. If this causes flakiness, run with `cargo test --lib config -- --test-threads=1`.

- [ ] **Step 5: Commit**

```bash
cd flykeep-cli && git add -A && git commit -m "feat: implement CLI config loading from env vars and TOML file"
```

---

### Task 9: CLI HTTP client module (TDD)

**Files:**
- Modify: `flykeep-cli/src/client.rs`

- [ ] **Step 1: Write failing tests**

Write `flykeep-cli/src/client.rs`:

```rust
use serde::Deserialize;

pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct SecretResponse {
    pub path: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct ListResponse {
    pub paths: Vec<String>,
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        todo!()
    }

    pub async fn get_secret(&self, _path: &str) -> Result<SecretResponse, String> {
        todo!()
    }

    pub async fn set_secret(&self, _path: &str, _value: &str) -> Result<(), String> {
        todo!()
    }

    pub async fn list_secrets(&self, _prefix: &str) -> Result<ListResponse, String> {
        todo!()
    }

    pub async fn delete_secret(&self, _path: &str) -> Result<(), String> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_get_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("path", "/ns/dev/app/KEY"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"path": "/ns/dev/app/KEY", "value": "secret-val"})),
            )
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        let res = client.get_secret("/ns/dev/app/KEY").await.expect("test: get");
        assert_eq!(res.path, "/ns/dev/app/KEY");
        assert_eq!(res.value, "secret-val");
    }

    #[tokio::test]
    async fn test_get_secret_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "not found"})),
            )
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        let result = client.get_secret("/ns/dev/app/MISSING").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/secrets"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        client
            .set_secret("/ns/dev/app/KEY", "val")
            .await
            .expect("test: set");
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("prefix", "/ns/dev/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"paths": ["/ns/dev/app/A", "/ns/dev/app/B"]})),
            )
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        let res = client.list_secrets("/ns/dev/").await.expect("test: list");
        assert_eq!(res.paths.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/secrets"))
            .and(query_param("path", "/ns/dev/app/KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        client
            .delete_secret("/ns/dev/app/KEY")
            .await
            .expect("test: delete");
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/secrets"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "not found"})),
            )
            .mount(&mock_server)
            .await;

        let client = Client::new(&mock_server.uri(), "test-token");
        let result = client.delete_secret("/ns/dev/app/MISSING").await;
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd flykeep-cli && cargo test --lib client`
Expected: all 6 tests panic with `not yet implemented`

- [ ] **Step 3: Implement the Client**

Replace the function bodies:

```rust
use serde::Deserialize;
use serde_json::json;

pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct SecretResponse {
    pub path: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct ListResponse {
    pub paths: Vec<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_secret(&self, path: &str) -> Result<SecretResponse, String> {
        let res = self
            .http
            .get(format!("{}/secrets", self.base_url))
            .query(&[("path", path)])
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }

        res.json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))
    }

    pub async fn set_secret(&self, path: &str, value: &str) -> Result<(), String> {
        let res = self
            .http
            .put(format!("{}/secrets", self.base_url))
            .header("authorization", format!("Bearer {}", self.token))
            .json(&json!({"path": path, "value": value}))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }

        Ok(())
    }

    pub async fn list_secrets(&self, prefix: &str) -> Result<ListResponse, String> {
        let res = self
            .http
            .get(format!("{}/secrets", self.base_url))
            .query(&[("prefix", prefix)])
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }

        res.json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))
    }

    pub async fn delete_secret(&self, path: &str) -> Result<(), String> {
        let res = self
            .http
            .delete(format!("{}/secrets", self.base_url))
            .query(&[("path", path)])
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }

        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd flykeep-cli && cargo test --lib client`
Expected: all 6 tests pass

- [ ] **Step 5: Commit**

```bash
cd flykeep-cli && git add -A && git commit -m "feat: implement HTTP client with wiremock tests"
```

---

### Task 10: CLI commands and output formatting (TDD)

**Files:**
- Modify: `flykeep-cli/src/main.rs`

- [ ] **Step 1: Write output formatting tests**

Replace `flykeep-cli/src/main.rs`:

```rust
mod client;
mod config;

use clap::{Parser, Subcommand, ValueEnum};
use client::{Client, ListResponse, SecretResponse};

#[derive(Parser)]
#[command(name = "flykeep", about = "CLI client for flykeep secret store")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: table or env
    #[arg(long, default_value = "table", global = true)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch and print a single secret
    Get { path: String },
    /// Create or update a secret
    Set { path: String, value: String },
    /// List secret paths under a prefix
    List { prefix: String },
    /// Delete a secret
    Delete { path: String },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Env,
}

fn format_get_table(resp: &SecretResponse) -> String {
    use comfy_table::{Table, ContentArrangement};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["PATH", "VALUE"]);
    table.add_row(vec![&resp.path, &resp.value]);
    table.to_string()
}

fn format_get_env(resp: &SecretResponse) -> String {
    let key = resp.path.rsplit('/').next().unwrap_or(&resp.path);
    format!("{key}={}", resp.value)
}

fn format_list_table(resp: &ListResponse) -> String {
    use comfy_table::{Table, ContentArrangement};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["PATH"]);
    for path in &resp.paths {
        table.add_row(vec![path]);
    }
    table.to_string()
}

fn format_list_env(resp: &ListResponse) -> String {
    resp.paths
        .iter()
        .map(|p| p.rsplit('/').next().unwrap_or(p))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let config = config::load_config()?;
    let client = Client::new(&config.server_url, &config.admin_token);

    match cli.command {
        Commands::Get { path } => {
            let resp = client.get_secret(&path).await?;
            match cli.format {
                OutputFormat::Table => println!("{}", format_get_table(&resp)),
                OutputFormat::Env => println!("{}", format_get_env(&resp)),
            }
        }
        Commands::Set { path, value } => {
            client.set_secret(&path, &value).await?;
            println!("ok");
        }
        Commands::List { prefix } => {
            let resp = client.list_secrets(&prefix).await?;
            match cli.format {
                OutputFormat::Table => println!("{}", format_list_table(&resp)),
                OutputFormat::Env => println!("{}", format_list_env(&resp)),
            }
        }
        Commands::Delete { path } => {
            client.delete_secret(&path).await?;
            println!("ok");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_get_table() {
        let resp = SecretResponse {
            path: "/ns/dev/app/DB_URL".to_string(),
            value: "postgres://localhost".to_string(),
        };
        let output = format_get_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("VALUE"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("postgres://localhost"));
    }

    #[test]
    fn test_format_get_env() {
        let resp = SecretResponse {
            path: "/ns/dev/app/DB_URL".to_string(),
            value: "postgres://localhost".to_string(),
        };
        let output = format_get_env(&resp);
        assert_eq!(output, "DB_URL=postgres://localhost");
    }

    #[test]
    fn test_format_list_table() {
        let resp = ListResponse {
            paths: vec![
                "/ns/dev/app/DB_URL".to_string(),
                "/ns/dev/app/API_KEY".to_string(),
            ],
        };
        let output = format_list_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("/ns/dev/app/API_KEY"));
    }

    #[test]
    fn test_format_list_env() {
        let resp = ListResponse {
            paths: vec![
                "/ns/dev/app/DB_URL".to_string(),
                "/ns/dev/app/API_KEY".to_string(),
            ],
        };
        let output = format_list_env(&resp);
        assert_eq!(output, "DB_URL\nAPI_KEY");
    }

    #[test]
    fn test_format_get_env_extracts_last_segment() {
        let resp = SecretResponse {
            path: "/a/b/c/MY_SECRET".to_string(),
            value: "val".to_string(),
        };
        assert_eq!(format_get_env(&resp), "MY_SECRET=val");
    }
}
```

Note: `format_get_env` and `format_list_env` use `rsplit('/').next().unwrap_or(...)` — this is `unwrap_or`, not `unwrap()`. It provides a fallback and cannot panic.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd flykeep-cli && cargo test --lib`
Expected: all formatting tests pass (5 tests), plus config tests (4) and client tests (6)

- [ ] **Step 3: Verify CLI compiles and shows help**

Run: `cd flykeep-cli && cargo run -- --help`
Expected: shows usage with get, set, list, delete subcommands and `--format` flag

- [ ] **Step 4: Commit**

```bash
cd flykeep-cli && git add -A && git commit -m "feat: implement CLI commands with table and env output formats"
```

---

### Task 11: Deployment files

**Files:**
- Create: `flykeep-server/Dockerfile`
- Create: `flykeep-server/fly.toml`

- [ ] **Step 1: Create Dockerfile**

Write `flykeep-server/Dockerfile`:

```dockerfile
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/flykeep-server /usr/local/bin/
EXPOSE 8080
CMD ["flykeep-server"]
```

- [ ] **Step 2: Create fly.toml**

Write `flykeep-server/fly.toml`:

```toml
app = "flykeep"
primary_region = "ord"

[build]

[env]
  FLYKEEP_DB_PATH = "/data/vault.db"
  FLYKEEP_PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

[mounts]
  source = "flykeep_data"
  destination = "/data"
```

- [ ] **Step 3: Generate Cargo.lock for Dockerfile**

Run: `cd flykeep-server && cargo generate-lockfile`

- [ ] **Step 4: Verify Docker build (optional — requires Docker)**

Run: `cd flykeep-server && docker build -t flykeep-server .`
Expected: builds successfully

- [ ] **Step 5: Commit**

```bash
cd flykeep-server && git add Dockerfile fly.toml Cargo.lock && git commit -m "feat: add Dockerfile and fly.toml for Fly.io deployment"
```

---

## Deployment Checklist (post-implementation)

After all tasks are complete:

1. `fly launch --no-deploy` — create the app on Fly
2. `fly volumes create flykeep_data --region ord --size 1` — create storage volume
3. `fly secrets set FLYKEEP_ENCRYPTION_KEY=$(openssl rand -hex 32) FLYKEEP_ADMIN_TOKEN=$(openssl rand -hex 16)` — set secrets
4. `fly deploy` — deploy the server
5. Test: `curl -H "Authorization: Bearer <token>" https://flykeep.fly.dev/secrets?path=/test/dev/KEY` — should return 404 (no secrets yet)
