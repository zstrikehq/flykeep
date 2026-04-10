# Read Token Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace IP-based network trust with an explicit read token, rename the CLI token field from `admin_token` to `token`.

**Architecture:** Server gains `FLYKEEP_READ_TOKEN` env var and `ReadOnly` auth level. `check_auth()` takes both tokens instead of a remote IP. CLI config renames `FLYKEEP_ADMIN_TOKEN` → `FLYKEEP_TOKEN` — the client doesn't distinguish token type; the server enforces access level.

**Tech Stack:** Rust, Salvo 0.77, existing flykeep-server and flykeep-cli crates.

---

## Files changed

| File | Change |
|---|---|
| `flykeep-server/src/auth.rs` | Remove `NetworkRead`/`is_fly_private_network`, add `ReadOnly`, update `check_auth` signature and middleware |
| `flykeep-server/src/main.rs` | Add `read_token` to `AppState`, load `FLYKEEP_READ_TOKEN` |
| `flykeep-server/src/routes.rs` | Update test setup + add ReadOnly auth tests |
| `flykeep-cli/src/config.rs` | Rename `admin_token` → `token`, `FLYKEEP_ADMIN_TOKEN` → `FLYKEEP_TOKEN` |
| `flykeep-cli/src/main.rs` | Update `config.admin_token` → `config.token` |

---

## Task 1: Server auth refactor

**Files:**
- Modify: `flykeep-server/src/auth.rs`
- Modify: `flykeep-server/src/main.rs`
- Modify: `flykeep-server/src/routes.rs` (test setup only)

These three files must change together — `AppState` (main.rs) and the middleware (auth.rs) are coupled.

- [ ] **Step 1: Replace `flykeep-server/src/auth.rs` entirely**

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum AuthLevel {
    Admin,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
}

/// Pure auth decision — no HTTP dependency, fully testable.
pub fn check_auth(
    auth_header: Option<&str>,
    admin_token: &str,
    read_token: &str,
) -> Result<AuthLevel, AuthError> {
    if let Some(header) = auth_header {
        let token = header.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
        if token == admin_token {
            return Ok(AuthLevel::Admin);
        }
        if token == read_token {
            return Ok(AuthLevel::ReadOnly);
        }
        return Err(AuthError::Unauthorized);
    }
    Err(AuthError::Forbidden)
}

use salvo::http::StatusCode;
use salvo::prelude::*;
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

        match check_auth(auth_header, &self.state.admin_token, &self.state.read_token) {
            Ok(level) => {
                depot.inject(level);
                depot.inject(self.state.clone());
                ctrl.call_next(req, depot, res).await;
            }
            Err(AuthError::Unauthorized) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(salvo::writing::Json(
                    serde_json::json!({"error": "unauthorized"}),
                ));
                ctrl.skip_rest();
            }
            Err(AuthError::Forbidden) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(salvo::writing::Json(
                    serde_json::json!({"error": "forbidden"}),
                ));
                ctrl.skip_rest();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_admin_token() {
        let result = check_auth(Some("Bearer admin-tok"), "admin-tok", "read-tok");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_valid_read_token() {
        let result = check_auth(Some("Bearer read-tok"), "admin-tok", "read-tok");
        assert_eq!(result, Ok(AuthLevel::ReadOnly));
    }

    #[test]
    fn test_invalid_token() {
        let result = check_auth(Some("Bearer wrong"), "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_malformed_auth_header() {
        let result = check_auth(Some("Basic abc123"), "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_no_token_returns_forbidden() {
        let result = check_auth(None, "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_read_token_is_readonly_not_admin() {
        let result = check_auth(Some("Bearer read-tok"), "admin-tok", "read-tok");
        assert_ne!(result, Ok(AuthLevel::Admin));
        assert_eq!(result, Ok(AuthLevel::ReadOnly));
    }
}
```

- [ ] **Step 2: Replace `flykeep-server/src/main.rs` entirely**

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
    pub read_token: String,
}

fn load_config() -> Result<(String, String, String, String, u16), String> {
    let _ = dotenvy::dotenv();
    let encryption_key_hex = std::env::var("FLYKEEP_ENCRYPTION_KEY")
        .map_err(|_| "FLYKEEP_ENCRYPTION_KEY is required".to_string())?;
    let admin_token = std::env::var("FLYKEEP_ADMIN_TOKEN")
        .map_err(|_| "FLYKEEP_ADMIN_TOKEN is required".to_string())?;
    let read_token = std::env::var("FLYKEEP_READ_TOKEN")
        .map_err(|_| "FLYKEEP_READ_TOKEN is required".to_string())?;
    let db_path = std::env::var("FLYKEEP_DB_PATH")
        .unwrap_or_else(|_| "./vault.db".to_string());
    let port: u16 = std::env::var("FLYKEEP_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .map_err(|e| format!("invalid FLYKEEP_PORT: {e}"))?;
    Ok((encryption_key_hex, admin_token, read_token, db_path, port))
}

pub fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid FLYKEEP_ENCRYPTION_KEY hex: {e}"))?;
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
    let (encryption_key_hex, admin_token, read_token, db_path, port) =
        load_config().expect("startup: failed to load config");
    let encryption_key = parse_encryption_key(&encryption_key_hex)
        .expect("startup: failed to parse encryption key");
    let database = Database::init(&db_path)
        .expect("startup: failed to initialize database");
    let state = Arc::new(AppState {
        db: Arc::new(database),
        encryption_key,
        admin_token,
        read_token,
    });
    let router = routes::create_router(state);
    let bind_addr = format!("0.0.0.0:{port}");
    eprintln!("flykeep-server listening on {bind_addr}");
    use salvo::Listener;
    let acceptor = salvo::conn::TcpListener::new(&bind_addr).bind().await;
    salvo::Server::new(acceptor).serve(router).await;
}
```

- [ ] **Step 3: Update the test setup in `flykeep-server/src/routes.rs`**

Find the `setup_service()` function in the `#[cfg(test)]` block. It currently constructs `AppState` without a `read_token`. Add the field:

Find this block:
```rust
        let state = Arc::new(AppState {
            db: Arc::new(db),
            encryption_key: test_key(),
            admin_token: test_token(),
        });
```

Replace with:
```rust
        let state = Arc::new(AppState {
            db: Arc::new(db),
            encryption_key: test_key(),
            admin_token: test_token(),
            read_token: "test-read-token".to_string(),
        });
```

- [ ] **Step 4: Add ReadOnly auth tests to `flykeep-server/src/routes.rs`**

In the `#[cfg(test)] mod tests` block, add these three new tests after the existing `test_no_auth_from_local_ip_returns_403` test:

```rust
    #[tokio::test]
    async fn test_read_token_can_get() {
        let (service, _dir) = setup_service();
        // First put a secret using the admin token
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", auth_header(), true)
            .json(&serde_json::json!({"path": "/ns/dev/app/KEY", "value": "secret"}))
            .send(&service)
            .await;

        // Then read it using the read token
        let mut res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .add_header("authorization", "Bearer test-read-token", true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
        let body: serde_json::Value = res.take_json().await.expect("test: parse json");
        assert_eq!(body["value"], "secret");
    }

    #[tokio::test]
    async fn test_read_token_cannot_put() {
        let (service, _dir) = setup_service();
        let res = TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", "Bearer test-read-token", true)
            .json(&serde_json::json!({"path": "/ns/dev/app/KEY", "value": "val"}))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_read_token_cannot_delete() {
        let (service, _dir) = setup_service();
        let res = TestClient::delete("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .add_header("authorization", "Bearer test-read-token", true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::FORBIDDEN);
    }
```

- [ ] **Step 5: Verify it compiles**

Run: `cd flykeep-server && cargo check 2>&1`
Expected: no errors

- [ ] **Step 6: Run all server tests**

Run: `cd flykeep-server && cargo test 2>&1 | tail -5`
Expected: all tests pass. New count: auth (6), routes (21), db (8), crypto (5) = 40 total.

Note: The total drops from 43 to 40 because 6 IP-based auth tests were removed and 3 ReadOnly route tests were added (net -3 + auth module now has 6 instead of 12 = net -6 from auth, +3 from routes = -3 total from before).

- [ ] **Step 7: Commit**

```bash
git add flykeep-server/src/auth.rs flykeep-server/src/main.rs flykeep-server/src/routes.rs
git commit -m "feat: replace network trust with read token, add ReadOnly auth level"
```

---

## Task 2: CLI config rename

**Files:**
- Modify: `flykeep-cli/src/config.rs`

- [ ] **Step 1: Write the updated tests first**

Replace `flykeep-cli/src/config.rs` with:

```rust
use serde::Deserialize;
use std::path::PathBuf;

pub struct Config {
    pub server_url: String,
    pub token: String,
}

#[derive(Deserialize)]
struct FileConfig {
    server_url: Option<String>,
    token: Option<String>,
}

pub fn load_config() -> Result<Config, String> {
    let _ = dotenvy::dotenv();

    let env_url = std::env::var("FLYKEEP_SERVER_URL").ok();
    let env_token = std::env::var("FLYKEEP_TOKEN").ok();

    if let (Some(url), Some(token)) = (&env_url, &env_token) {
        return Ok(Config {
            server_url: url.clone(),
            token: token.clone(),
        });
    }

    let file_config = config_file_path().and_then(|p| {
        if p.exists() {
            load_from_file(&p).ok()
        } else {
            None
        }
    });

    let server_url = env_url
        .or_else(|| file_config.as_ref().map(|c| c.server_url.clone()))
        .ok_or("FLYKEEP_SERVER_URL not set and not found in config file")?;

    let token = env_token
        .or_else(|| file_config.as_ref().map(|c| c.token.clone()))
        .ok_or("FLYKEEP_TOKEN not set and not found in config file")?;

    Ok(Config { server_url, token })
}

pub(crate) fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("flykeep")
            .join("config.toml"),
    )
}

pub(crate) fn load_from_file(path: &std::path::Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file: {e}"))?;
    let file_config: FileConfig = toml::from_str(&content)
        .map_err(|e| format!("failed to parse config file: {e}"))?;
    let server_url = file_config
        .server_url
        .ok_or("server_url missing in config file")?;
    let token = file_config.token.ok_or("token missing in config file")?;
    Ok(Config { server_url, token })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_config_from_env_vars() {
        std::env::set_var("FLYKEEP_SERVER_URL", "http://test:8080");
        std::env::set_var("FLYKEEP_TOKEN", "test-token");
        let config = load_config().expect("test: load config");
        assert_eq!(config.server_url, "http://test:8080");
        assert_eq!(config.token, "test-token");
        std::env::remove_var("FLYKEEP_SERVER_URL");
        std::env::remove_var("FLYKEEP_TOKEN");
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(b"server_url = \"http://file:8080\"\ntoken = \"file-token\"\n")
            .expect("test: write file");
        let config = load_from_file(&file_path).expect("test: load from file");
        assert_eq!(config.server_url, "http://file:8080");
        assert_eq!(config.token, "file-token");
    }

    #[test]
    fn test_load_from_file_missing_token() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(b"server_url = \"http://file:8080\"\n")
            .expect("test: write file");
        let result = load_from_file(&file_path);
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Verify tests fail (old env var name)**

Run: `cd flykeep-cli && cargo test config -- --test-threads=1 2>&1`
Expected: `test_config_from_env_vars` fails (still uses `FLYKEEP_ADMIN_TOKEN` internally if not fully replaced — but since we've replaced the file, it should pass. Run to verify.)

Actually since you're replacing the whole file, tests should pass immediately. Run and confirm 3 tests pass.

- [ ] **Step 3: Run all CLI tests**

Run: `cd flykeep-cli && cargo check 2>&1`
Expected: compile error — `main.rs` still references `config.admin_token` which no longer exists. This is expected and fixed in Task 3.

- [ ] **Step 4: Commit config.rs**

```bash
git add flykeep-cli/src/config.rs
git commit -m "feat: rename CLI token field from admin_token to token, env var FLYKEEP_TOKEN"
```

---

## Task 3: CLI main.rs token reference

**Files:**
- Modify: `flykeep-cli/src/main.rs`

- [ ] **Step 1: Update the token reference in `run()`**

In `flykeep-cli/src/main.rs`, find line 80:
```rust
    let client = Client::new(&config.server_url, &config.admin_token);
```

Replace with:
```rust
    let client = Client::new(&config.server_url, &config.token);
```

- [ ] **Step 2: Verify it compiles**

Run: `cd flykeep-cli && cargo check 2>&1`
Expected: no errors

- [ ] **Step 3: Run all CLI tests**

Run: `cd flykeep-cli && cargo test -- --test-threads=1 2>&1 | tail -5`
Expected: all 14 tests pass (config: 3, client: 6, main: 5)

- [ ] **Step 4: Commit**

```bash
git add flykeep-cli/src/main.rs
git commit -m "fix: use config.token instead of config.admin_token in CLI"
```

---

## Final verification

- [ ] **Run all server tests**

```bash
cd flykeep-server && cargo test 2>&1 | tail -3
```
Expected: 40 tests pass, 0 failed

- [ ] **Run all CLI tests**

```bash
cd flykeep-cli && cargo test -- --test-threads=1 2>&1 | tail -3
```
Expected: 14 tests pass, 0 failed
