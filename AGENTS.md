# flykeep

Self-hosted secret store. Rust workspace with two crates.

## Layout

- `flykeep-server/` — HTTP server (Salvo). AES-256-GCM encryption, SQLite storage.
  - `crypto.rs` — encrypt/decrypt
  - `db.rs` — SQLite CRUD
  - `auth.rs` — token auth middleware (Admin + ReadOnly levels)
  - `routes.rs` — handlers for `/secrets`, `/alive`, `/auth/verify`
  - `main.rs` — server wiring
- `flykeep-cli/` — CLI, binary name `flykeep`.
  - `client.rs` — HTTP client
  - `config.rs` — env vars + `~/.config/flykeep/config.toml`
  - `main.rs` — clap commands (`set`, `get`, `list`, `delete`, `auth`, `version`)

## Build & test

```sh
cargo build --manifest-path flykeep-server/Cargo.toml
cargo test --manifest-path flykeep-server/Cargo.toml

cargo build --manifest-path flykeep-cli/Cargo.toml
cargo test --manifest-path flykeep-cli/Cargo.toml
```

## Coding rules

- No `.unwrap()` or `.expect()` in non-test code — propagate errors properly.
- No `unsafe` blocks.
- CLI tests use `wiremock`. Server tests use `tempfile` for SQLite fixtures.

## Changelog

Always update `CHANGELOG.md` when making user-visible changes (features, fixes, breaking changes, CLI/API changes). Add entries under an `## [Unreleased]` section if one exists, or create one. Do not wait to be asked.

## Release

Tag `vX.Y.Z` triggers `.github/workflows/release.yml`, which builds macOS arm64/x86_64 and Linux x86_64 binaries and creates a GitHub release.

Before tagging: bump `version` in both `flykeep-server/Cargo.toml` and `flykeep-cli/Cargo.toml`, and move `[Unreleased]` entries in `CHANGELOG.md` under the new version heading with the release date.

## Deployment

Server deploys to Fly.io via `flykeep-server/fly.toml` and `Dockerfile`. Required secrets: `FLYKEEP_ENCRYPTION_KEY`, `FLYKEEP_ADMIN_TOKEN`, `FLYKEEP_READ_TOKEN`.
