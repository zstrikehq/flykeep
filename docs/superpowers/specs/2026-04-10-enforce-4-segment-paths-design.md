# flykeep — Enforce 4-Segment Path Grammar Design Spec

## Overview

Tighten secret path validation from "≥2 segments" to exactly 4 segments, following the convention `/workspace/project/env/key`. Ships as the next release under `[Unreleased]`. Breaking change — the first one where fewer than 4 or more than 4 segments is an error.

This spec lands independently of the upcoming multi-user / service accounts work; it's a small, focused tightening that stabilises the path shape those later changes will build on.

---

## Motivation

The current `validate_path` (in `flykeep-server/src/routes.rs`) rejects paths with 0 or 1 segments but accepts anything with 2 or more. The original PRD documented a 4-segment shape (`/namespace/environment/appname/KEY`) but never had the code enforce it. The result: inconsistent path shapes in practice and no stable structure for the upcoming authorization layer to reason about.

This spec does two things at once:

1. **Enforce exactly 4 segments** in `validate_path`.
2. **Rename the canonical segment labels** to `workspace`, `project`, `env`, `key` and update the PRD to match. This is the naming the upcoming accounts/Cedar work will expose as Cedar entity attributes, so locking it in now avoids a second round of documentation churn later.

Why do both in one spec: the rename is a documentation-only change that makes no sense without the 4-segment enforcement, and the enforcement has no reason to keep the old PRD names. Shipping them separately would cause temporary inconsistency between code and docs.

Benefits:

- Catches typos and sloppy path construction earlier with a clear error message.
- Gives the upcoming accounts/Cedar work a stable structure to expose as entity attributes without handling variable-length paths.
- Aligns code, PRD, README, and examples on one shape and one vocabulary.

---

## Path Grammar (new)

```
/<workspace>/<project>/<env>/<key>
```

| Rule | |
|---|---|
| Leading `/` | required |
| Trailing `/` | rejected |
| Segment count | exactly 4 |
| Segment content | non-empty; lowercased by server (existing behavior) |
| Charset | unchanged from today (no additional tightening in this spec) |

Anything with fewer than 4 or more than 4 segments is rejected with `400` and a message that names the expected shape.

### Segment semantics (informational)

The server treats each segment as an opaque string. The names below are the convention, not enforced meanings.

| Position | Name | Example | Meaning |
|---|---|---|---|
| 1 | `workspace` | `acme` | Top-level grouping — team, org, or logical isolation boundary |
| 2 | `project` | `billing` | Deployable unit, application, or service |
| 3 | `env` | `prod` | Lifecycle stage — `dev`, `stage`, `prod`, etc. |
| 4 | `key` | `DB_URL` | The secret's name |

---

## Prefix Grammar (unchanged)

`validate_prefix` stays loose:

- Must start with `/`
- Must end with `/`
- Any number of segments (including `/` alone for "list everything")

Listing a prefix that implies fewer than 4 segments is still legal (e.g. `list /acme/billing/`). The 4-segment rule applies only to fully-qualified secret paths, not to the prefix used on list queries.

---

## Server Changes

### `flykeep-server/src/routes.rs`

`validate_path` updated:

**Before:**
```rust
let segments: Vec<&str> = path[1..].split('/').collect();
if segments.len() < 2 {
    return Err("path must have at least 2 segments".to_string());
}
if segments.iter().any(|s| s.is_empty()) {
    return Err("path must not contain empty segments".to_string());
}
```

**After:**
```rust
let segments: Vec<&str> = path[1..].split('/').collect();
if segments.len() != 4 {
    return Err(
        "path must have exactly 4 segments: /workspace/project/env/key".to_string(),
    );
}
if segments.iter().any(|s| s.is_empty()) {
    return Err("path must not contain empty segments".to_string());
}
```

### Test updates in `routes.rs`

- **Remove**: `test_valid_path_two_segments` — no longer valid.
- **Keep**: `test_valid_path_four_segments`.
- **Add**: `test_path_three_segments_rejected`, `test_path_five_segments_rejected`.
- **Add**: `test_path_error_message_mentions_format` — sanity check that the error string mentions the expected shape, so CLI users get a useful hint.
- Existing tests that already use 4-segment paths (`/ns/dev/app/KEY`) continue to pass unchanged.

### `flykeep-server/src/db.rs` — startup sanity check

`Database::init` runs a one-shot count after `CREATE TABLE IF NOT EXISTS` and emits a single warning log line if any existing row's `path` doesn't match the new shape:

```rust
let bad_count: i64 = conn.query_row(
    "SELECT COUNT(*) FROM secrets
     WHERE (LENGTH(path) - LENGTH(REPLACE(path, '/', ''))) != 4",
    [],
    |row| row.get(0),
).map_err(|e| format!("startup path audit failed: {e}"))?;
if bad_count > 0 {
    eprintln!(
        "warning: {bad_count} existing secrets have paths that don't match \
         the new 4-segment grammar (/workspace/project/env/key); they will \
         be unreachable via the API until recreated with a valid path"
    );
}
```

No automated migration. Operators with mismatched data must recreate secrets under valid paths. The count-based warning gives them a signal at startup.

### New test in `db.rs`

- `test_init_warns_on_mismatched_paths` — seed a `secrets` table with a 2-segment path, re-init, assert the row is still present (init does not delete) and the count query returns the expected number. The warning goes to stderr and isn't asserted on directly.

---

## CLI Changes

`flykeep-cli` does no path validation of its own today — the server rejects bad paths with `400`. No code change is required to enforce the new rule.

Documentation-only updates:

### `README.md` / CLI help text

Command examples updated to 4-segment paths:

```sh
flykeep set /acme/billing/prod/DB_URL "postgres://..."
flykeep get /acme/billing/prod/DB_URL
flykeep list /acme/billing/
flykeep delete /acme/billing/prod/DB_URL
```

Any occurrence of `/ns/dev/app/KEY`-style examples in the README updated to the `workspace/project/env/key` convention for internal consistency.

---

## PRD Update

`prd.md` — "Path Rules" section:

**Before:**
```
- Must start with `/`
- Format: `/namespace/environment/appname/KEY`
- Minimum 2 segments
- No trailing slash
- Case-sensitive
- Invalid paths return `400`
```

**After:**
```
- Must start with `/`
- Format: `/workspace/project/env/key` — exactly 4 segments
- No trailing slash
- Lowercased by the server
- Invalid paths return `400`
```

---

## CHANGELOG

Add under `[Unreleased]` (creating the section if it doesn't exist):

```
## [Unreleased]

### Changed

- **Breaking:** secret paths now require exactly 4 segments:
  `/workspace/project/env/key`. Paths with fewer or more segments are
  rejected with `400`. Existing secrets stored under other shapes will
  remain in the database but become unreachable via the API until
  recreated with a valid path. The server logs a one-line warning at
  startup if any mismatched rows are present.
```

---

## Out of Scope

- Charset tightening per segment (still permissive).
- Enforcing any particular vocabulary for `env` (no "must be one of dev/stage/prod").
- Automated migration or rewrite of existing mis-shaped rows.
- Exposing the 4 segments as structured fields in API responses — not needed until the accounts/Cedar work lands.
- Any change to authentication, authorization, or the existing token model. That lands in the separate multi-user/service accounts spec.
