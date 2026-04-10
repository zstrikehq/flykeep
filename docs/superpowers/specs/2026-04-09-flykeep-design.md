# flykeep — Design Spec

## Overview

Two independent Rust projects. A secret store HTTP server deployed on Fly.io and a CLI client for managing secrets.

---

## Projects

| Project | Purpose |
|---|---|
| `flykeep-server` | HTTP API + SQLite + AES-256-GCM encryption. Deployed on Fly.io with public port. |
| `flykeep-cli` | CLI client. Talks to `flykeep-server` over HTTP. Always sends admin token. |

Two independent Cargo projects. No workspace, no shared crates.

---

## flykeep-server

### File Structure

```
flykeep-server/
  src/
    main.rs        -- startup, config loading, router setup
    auth.rs        -- middleware: token check + peer IP check
    crypto.rs      -- AES-256-GCM encrypt/decrypt
    db.rs          -- SQLite init, CRUD operations
    routes.rs      -- GET/PUT/DELETE /secrets handlers
  Cargo.toml
  Dockerfile
  fly.toml
```

### Configuration

| Env Var | Required | Default | Description |
|---|---|---|---|
| `FLYKEEP_ENCRYPTION_KEY` | Yes | -- | 64-char hex string (32 bytes). Used to encrypt/decrypt values. |
| `FLYKEEP_ADMIN_TOKEN` | Yes | -- | Bearer token required for write ops and public access. |
| `FLYKEEP_DB_PATH` | No | `./vault.db` | Path to SQLite file. |
| `FLYKEEP_PORT` | No | `8080` | Port to listen on. |

All required vars validated at startup. Server fails fast if missing or invalid.

### Data Model

```sql
CREATE TABLE IF NOT EXISTS secrets (
  path       TEXT PRIMARY KEY,
  value      BLOB NOT NULL,
  nonce      BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

- `value`: encrypted ciphertext (raw bytes, not valid UTF-8)
- `nonce`: random 12-byte nonce used during encryption
- Timestamps: Unix epoch seconds
- All plaintext values are strings. Typed values (numbers, booleans) are not supported — the consuming app parses as needed.

### Path Rules

- Must start with `/`
- Format: `/namespace/environment/appname/KEY`
- Minimum 2 segments
- No trailing slash
- Case-sensitive
- Invalid paths return `400 {"error": "..."}`

### Auth Model

Auth middleware runs on every request. Peer IP obtained via `req.remote_addr()`.

```
Request arrives
  |
  +-- Has Authorization header?
  |     +-- Token matches FLYKEEP_ADMIN_TOKEN -> allow GET/PUT/DELETE
  |     +-- Token doesn't match -> 401 {"error": "unauthorized"}
  |
  +-- No Authorization header
        +-- Peer IP in fdaa::/8 -> allow GET only (PUT/DELETE -> 403)
        +-- Peer IP not in fdaa::/8 -> 403 {"error": "forbidden"}
```

| Auth type | GET (read) | GET (list) | PUT | DELETE |
|---|---|---|---|---|
| Admin token | Yes | Yes | Yes | Yes |
| Network (`fdaa::/8`) | Yes | Yes | No (403) | No (403) |
| No token, public IP | 403 | 403 | 403 | 403 |
| Invalid token | 401 | 401 | 401 | 401 |

Public clients cannot spoof `fdaa::/8` — TCP handshake prevents IP spoofing, and public traffic goes through Fly's edge proxy which terminates the connection.

### API

#### Read single secret

```
GET /secrets?path=/namespace/dev/myapp/DB_URL
```
```json
200: { "path": "/namespace/dev/myapp/DB_URL", "value": "plaintext" }
404: { "error": "not found" }
```

#### List secrets by prefix

```
GET /secrets?prefix=/namespace/dev/
```
```json
200: { "paths": ["/namespace/dev/myapp/DB_URL", "/namespace/dev/myapp/API_KEY"] }
```

Returns path names only, no values. Trailing slash required on prefix; reject without it (`400`).
Implemented as `SELECT path FROM secrets WHERE path LIKE '<prefix>%'`.

#### Create/update secret (admin token required)

```
PUT /secrets
Body: { "path": "/namespace/dev/myapp/DB_URL", "value": "plaintext" }
```
```json
200: { "ok": true }
```

Upsert via `ON CONFLICT` — on insert sets both `created_at` and `updated_at`, on update only changes `updated_at`. Preserves original creation timestamp.

#### Delete secret (admin token required)

```
DELETE /secrets?path=/namespace/dev/myapp/DB_URL
```
```json
200: { "ok": true }
404: { "error": "not found" }
```

### Error Format

All errors use a consistent simple format:

```json
{"error": "description of what went wrong"}
```

### Encryption

- Algorithm: AES-256-GCM
- Key: `FLYKEEP_ENCRYPTION_KEY` — 64-char hex string parsed into 32 bytes at startup
- Nonce: random 12 bytes generated per write via `OsRng`, stored in `nonce` column
- Plaintext never written to disk
- Argon2id not needed — the key is already a full 256-bit random key, not a password

**`crypto.rs` functions:**

- `encrypt(key: &[u8; 32], plaintext: &str) -> (Vec<u8>, Vec<u8>)` — returns (ciphertext, nonce)
- `decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> String` — returns plaintext

### Database (`db.rs`)

SQLite via `rusqlite` with `bundled` feature (compiles SQLite from source, no system dependency).

| Function | SQL | Notes |
|---|---|---|
| `init(path)` | `CREATE TABLE IF NOT EXISTS` | Called once at startup |
| `get_secret(path)` | `SELECT value, nonce FROM secrets WHERE path = ?` | Returns `Option` |
| `put_secret(path, value, nonce)` | `INSERT INTO secrets ... ON CONFLICT(path) DO UPDATE SET ...` | On insert: sets both timestamps. On update: only updates `updated_at`. |
| `list_secrets(prefix)` | `SELECT path FROM secrets WHERE path LIKE ?` | Appends `%` to prefix |
| `delete_secret(path)` | `DELETE FROM secrets WHERE path = ? RETURNING path` | RETURNING detects existence |

`rusqlite` is synchronous — each DB call wrapped in `tokio::task::spawn_blocking`. Single connection held in app state behind a `Mutex`.

### Dependencies

| Crate | Purpose |
|---|---|
| `salvo` | HTTP framework |
| `tokio` (full) | Async runtime |
| `rusqlite` (bundled) | SQLite |
| `aes-gcm` | AES-256-GCM encryption |
| `serde` + `serde_json` | JSON serialization |
| `dotenvy` | Env var loading |
| `hex` | Parse encryption key from hex |
| `rand` | Generate random nonces |

---

## flykeep-cli

### File Structure

```
flykeep-cli/
  src/
    main.rs        -- clap setup, command dispatch
    config.rs      -- load from env vars / config file
    client.rs      -- HTTP client wrapping reqwest calls
  Cargo.toml
```

### Configuration

Two sources, env vars take precedence over config file:

1. Env vars: `FLYKEEP_SERVER_URL`, `FLYKEEP_ADMIN_TOKEN`
2. Config file: `~/.config/flykeep/config.toml`

```toml
server_url = "http://flykeep.internal:8080"
admin_token = "your-token-here"
```

macOS and Linux only. No Windows support. Path hardcoded (no `dirs` crate).

Fail with clear error if neither source provides required values.

### Commands

```bash
flykeep get <path>                    # fetch and print one secret
flykeep set <path> <value>            # create or update a secret
flykeep list <prefix>                 # list secret paths under prefix
flykeep delete <path>                 # delete a secret
```

All commands send `Authorization: Bearer <token>`.

### Output Modes

Global flag: `--format <format>` (default: `table`)

**Table mode (default):**

```
flykeep get /ns/dev/myapp/DB_URL

+------------------------+----------+
| PATH                   | VALUE    |
+------------------------+----------+
| /ns/dev/myapp/DB_URL   | postgres |
+------------------------+----------+
```

```
flykeep list /ns/dev/myapp/

+------------------------+
| PATH                   |
+------------------------+
| /ns/dev/myapp/DB_URL   |
| /ns/dev/myapp/API_KEY  |
+------------------------+
```

**Env mode (`--format env`):**

```
flykeep get /ns/dev/myapp/DB_URL --format env
DB_URL=postgres

flykeep list /ns/dev/myapp/ --format env
DB_URL
API_KEY
```

Key extracted from the last segment of the path. Useful for piping: `flykeep get /ns/dev/myapp/DB_URL --format env >> .env`

### HTTP Client (`client.rs`)

Thin wrapper around `reqwest`. Functions: `get_secret`, `list_secrets`, `set_secret`, `delete_secret`. Every request includes the bearer token. Returns parsed response or user-friendly error to stderr with non-zero exit code.

### Dependencies

| Crate | Purpose |
|---|---|
| `reqwest` (rustls-tls) | HTTP client (no OpenSSL dependency) |
| `clap` (derive) | CLI argument parsing |
| `tokio` (rt-multi-thread, macros) | Async runtime for reqwest |
| `serde` + `serde_json` | JSON deserialization |
| `toml` | Parse config file |
| `comfy-table` | ASCII table output |
| `dotenvy` | Env var loading |

---

## Deployment

### Dockerfile (multi-stage, Alpine)

```dockerfile
# Stage 1: Build
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: Runtime
FROM alpine:latest
COPY --from=builder /app/target/release/flykeep-server /usr/local/bin/
CMD ["flykeep-server"]
```

`musl-dev` required in build stage for rusqlite's bundled SQLite C compilation.

### fly.toml

- Public HTTP service on port 8080
- Auto-stop/start for cost savings
- Mount Fly volume at `/data` for SQLite persistence
- Env: `FLYKEEP_DB_PATH=/data/vault.db`, `FLYKEEP_PORT=8080`

### Fly secrets

```bash
fly secrets set FLYKEEP_ENCRYPTION_KEY=<64-hex-chars> FLYKEEP_ADMIN_TOKEN=<token>
```

### CLI access

Server is publicly accessible. CLI connects directly using the server's public URL with admin token auth. No VPN or proxy required.

Internal Fly machines use `.internal` address for unauthenticated read access.

---

## Out of Scope (MVP)

- Key rotation
- Secret versioning
- TTL / expiry
- Audit log
- TLS (Fly handles transport)
- UI
- Multi-tenancy
- Read tokens
- Windows support
- Typed values (everything is strings)
