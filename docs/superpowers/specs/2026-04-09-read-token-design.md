# flykeep — Read Token Design Spec

## Overview

Add a `FLYKEEP_READ_TOKEN` to the server for read-only access. Remove IP-based network trust entirely. The CLI uses a single token (`FLYKEEP_TOKEN`) and lets the server enforce access level.

---

## Motivation

The previous auth model trusted any request from `fdaa::/8` (Fly private network) for unauthenticated reads. This was too broad — any Fly machine, even from other orgs, could theoretically reach the server if network isolation failed. Replacing this with an explicit read token gives you a credential you can share without granting write access.

---

## Auth Model (new)

| Condition | GET | PUT | DELETE |
|---|---|---|---|
| Valid admin token | ✅ | ✅ | ✅ |
| Valid read token | ✅ | 403 | 403 |
| No token | 403 | 403 | 403 |
| Invalid token | 401 | 401 | 401 |

No IP-based trust. All access requires a token.

---

## flykeep-server changes

### Configuration

| Env Var | Required | Description |
|---|---|---|
| `FLYKEEP_ENCRYPTION_KEY` | Yes | Unchanged |
| `FLYKEEP_ADMIN_TOKEN` | Yes | Full access |
| `FLYKEEP_READ_TOKEN` | Yes | Read-only access (GET) |
| `FLYKEEP_DB_PATH` | No | Unchanged |
| `FLYKEEP_PORT` | No | Unchanged |

### `AppState` (main.rs)

Add `read_token: String` field:

```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub encryption_key: [u8; 32],
    pub admin_token: String,
    pub read_token: String,
}
```

### `auth.rs`

**Remove:**
- `AuthLevel::NetworkRead` variant
- `is_fly_private_network()` function
- `remote_ip` parameter from `check_auth()`
- All IP-related tests

**Add:**
- `AuthLevel::ReadOnly` variant
- `read_token: &str` parameter to `check_auth()`

**New signature:**
```rust
pub fn check_auth(
    auth_header: Option<&str>,
    admin_token: &str,
    read_token: &str,
) -> Result<AuthLevel, AuthError>
```

**New logic:**
```
if header present:
  strip "Bearer " prefix → 401 if missing
  if token == admin_token → Admin
  if token == read_token → ReadOnly
  else → 401
else:
  → 403
```

**Updated `AuthMiddleware`:** Remove `remote_ip` extraction. Pass both tokens from `AppState` to `check_auth()`.

**Updated tests:**
- Remove: `test_no_token_fly_private_ipv6`, `test_admin_token_overrides_private_network`, `test_is_fly_private_*` (5 tests removed)
- Add: `test_valid_read_token`, `test_read_token_returns_readonly_level`, `test_invalid_token_returns_unauthorized`, `test_no_token_returns_forbidden` (4 tests added)

Net change: 12 → 11 tests in auth module.

### `routes.rs`

`put_secret` and `delete_secret` already check `auth_level != AuthLevel::Admin` — this still works correctly with `ReadOnly` replacing `NetworkRead`. No handler changes needed.

---

## flykeep-cli changes

### Config rename

`FLYKEEP_ADMIN_TOKEN` → `FLYKEEP_TOKEN`

Config file field rename: `admin_token` → `token`

```toml
server_url = "http://flykeep.fly.dev"
token = "your-token-here"
```

### `config.rs`

- Rename `Config.admin_token` → `Config.token`
- Rename env var from `FLYKEEP_ADMIN_TOKEN` → `FLYKEEP_TOKEN`
- Update error messages accordingly

### `client.rs`

- Rename `token` field reference in constructor (already named `token` internally — just update `Config` field access)

### `main.rs`

- Update `Client::new(&config.server_url, &config.admin_token)` → `Client::new(&config.server_url, &config.token)`

---

## Coding Constraints

- No `unwrap()`, no `unsafe`

---

## Token Format Convention

Tokens have no required format — the server matches by exact equality. By convention, prefix tokens to make their purpose obvious:

```bash
# Generate tokens
fly secrets set \
  FLYKEEP_ADMIN_TOKEN=admin_$(openssl rand -hex 16) \
  FLYKEEP_READ_TOKEN=read_$(openssl rand -hex 16)
```

This makes it immediately clear which token you're looking at in config files, logs, or when sharing credentials. Not enforced by the server.

---

## Out of Scope

- Multiple read tokens
- Token rotation
- CLI-side access level detection (server returns 403 for unauthorized ops)
