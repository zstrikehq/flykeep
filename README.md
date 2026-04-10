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
fly secrets set \
  FLYKEEP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  FLYKEEP_ADMIN_TOKEN=$(openssl rand -hex 24) \
  FLYKEEP_READ_TOKEN=$(openssl rand -hex 24)
```

## CLI

Install from [releases](https://github.com/zstrikehq/flykeep/releases) or build from source:

```
cd flykeep-cli
cargo build --release
```

### Setup

Option 1 — interactive:

```
flykeep auth
```

Prompts for server URL and token, validates credentials, and saves to `~/.config/flykeep/config.toml`.

Option 2 — environment variables:

```
export FLYKEEP_SERVER_URL=https://your-server.fly.dev
export FLYKEEP_TOKEN=your-token
```

Env vars take precedence over the config file.

### Usage

```
flykeep set /acme/myapp/prod/DB_URL postgres://localhost
flykeep get /acme/myapp/prod/DB_URL
flykeep list /acme/myapp/prod/
flykeep list /acme/myapp/prod/ --values
flykeep delete /acme/myapp/prod/DB_URL
```

### Output formats

```
flykeep list /acme/myapp/ --format table   # default, includes timestamps
flykeep list /acme/myapp/ --format env     # KEY=VALUE pairs (auto-fetches values)
flykeep list /acme/myapp/ --format json    # JSON array (auto-fetches values)
```

## Docker Entrypoint

Use flykeep to inject secrets as environment variables at container startup.

**docker-entrypoint.sh:**

```bash
#!/bin/sh
set -e
export $(flykeep list /acme/myapp/prod/ --format env)
exec "$@"
```

**Dockerfile:**

```dockerfile
COPY --from=flykeep /flykeep /usr/local/bin/flykeep
COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "server.js"]
```

Set `FLYKEEP_SERVER_URL` and `FLYKEEP_TOKEN` as environment variables in your container runtime.

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
