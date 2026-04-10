# flykeep

A self-hosted secret store. Secrets are encrypted with AES-256-GCM and stored in SQLite.

## Server

Requires environment variables:

```
FLYKEEP_ENCRYPTION_KEY=<64 hex chars>
FLYKEEP_ADMIN_TOKEN=<your-admin-token>
FLYKEEP_READ_TOKEN=<your-read-token>
FLYKEEP_DB_PATH=./vault.db        # optional, default: ./vault.db
FLYKEEP_PORT=8080                  # optional, default: 8080
```

Deploy with Docker or directly to [Fly.io](https://fly.io):

```
cd flykeep-server
# Change `app` in fly.toml to a unique name
fly deploy
fly secrets set FLYKEEP_ENCRYPTION_KEY=<64 hex chars> FLYKEEP_ADMIN_TOKEN=<token> FLYKEEP_READ_TOKEN=<token>
```

## CLI

Install from [releases](https://github.com/zstrikehq/flykeep/releases) or build from source:

```
cd flykeep-cli
cargo build --release
```

### Setup

```
flykeep auth
```

Prompts for server URL and token, validates credentials, and saves to `~/.config/flykeep/config.toml`.

### Usage

```
flykeep set /apps/myapp/db_url postgres://localhost
flykeep get /apps/myapp/db_url
flykeep list /apps/myapp/
flykeep list /apps/myapp/ --values
flykeep delete /apps/myapp/db_url
```

### Output formats

```
flykeep list /apps/ --format table   # default, includes timestamps
flykeep list /apps/ --format env     # KEY=value pairs
flykeep list /apps/ --format json
```

## API

All secret endpoints require `Authorization: Bearer <token>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/alive` | Health check (no auth) |
| GET | `/auth/verify` | Validate token |
| GET | `/secrets?path=/a/b` | Get a secret |
| GET | `/secrets?prefix=/a/` | List secrets |
| PUT | `/secrets` | Create/update a secret |
| DELETE | `/secrets?path=/a/b` | Delete a secret |

### Permissions

| Operation | Admin | Read |
|-----------|-------|------|
| Get secret | Yes | Yes |
| List secrets | Yes | Yes |
| Create/update secret | Yes | No |
| Delete secret | Yes | No |

## License

MIT
