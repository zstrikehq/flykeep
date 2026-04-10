# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] — unreleased

Running list of features landing under 0.1.0. Entries accumulate as work merges to `main`; the date is set when the version is tagged.

- Self-hosted secret store with AES-256-GCM encryption over SQLite.
- HTTP API with admin and read-only bearer tokens.
- CLI client (`flykeep`) with `get`, `set`, `list`, `delete`, `auth`, and `version` commands.
- Secret paths follow a fixed 4-segment grammar: `/workspace/project/env/key`.
- `/alive` health endpoint returns server version.
- `flykeep version` shows both client and server versions.
