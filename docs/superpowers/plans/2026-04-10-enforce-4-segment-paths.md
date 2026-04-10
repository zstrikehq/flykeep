# Enforce 4-Segment Path Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten secret path validation to require exactly 4 segments (`/workspace/project/env/key`) and align all documentation with the new canonical segment vocabulary.

**Architecture:** Single-line change to `validate_path`, a new helper method on `Database` to audit existing rows against the new rule, a one-shot warning from `main.rs` at startup, plus docs and CHANGELOG updates. No new modules, no dependencies, no breaking changes to the wire protocol beyond the validation rule itself.

**Tech Stack:** Rust 2021, Salvo HTTP server, rusqlite, tempfile (tests). Build/test via `cargo` with `--manifest-path flykeep-server/Cargo.toml`.

**Spec:** [`docs/superpowers/specs/2026-04-10-enforce-4-segment-paths-design.md`](../specs/2026-04-10-enforce-4-segment-paths-design.md)

---

## File Structure

| File | Role |
|---|---|
| `flykeep-server/src/routes.rs` | Holds `validate_path` — the single source of truth for the path rule. Tests live in the `mod tests` block at the bottom. |
| `flykeep-server/src/db.rs` | Holds the `Database` struct. Adds a single public method, `count_non_4_segment_paths`, used at startup for the audit log. |
| `flykeep-server/src/main.rs` | Startup wiring. Calls the audit method after `Database::init` and prints a single warning line to stderr if any rows don't match. |
| `prd.md` | Path Rules section + example paths throughout. Canonical vocabulary update. |
| `README.md` | CLI usage examples and docker entrypoint example. |
| `CHANGELOG.md` | Add `[Unreleased]` section describing the breaking change. |

---

## Task 1: Tighten `validate_path` to exactly 4 segments

**Files:**
- Modify: `flykeep-server/src/routes.rs` — `validate_path` body (around lines 34–49)
- Modify: `flykeep-server/src/routes.rs` — tests module (add 3 tests, remove 1)

This task is TDD: write the new tests first, watch them fail, then change the one line in `validate_path` that makes them pass, then remove the now-obsolete test.

- [ ] **Step 1: Add the three new failing tests**

Open `flykeep-server/src/routes.rs` and locate the existing `test_valid_path_four_segments` test in the `mod tests` block. Add these three tests immediately after it (they share the same style as existing tests in the file):

```rust
    #[test]
    fn test_path_three_segments_rejected() {
        assert!(validate_path("/ns/dev/app").is_err());
    }

    #[test]
    fn test_path_five_segments_rejected() {
        assert!(validate_path("/ns/dev/app/KEY/EXTRA").is_err());
    }

    #[test]
    fn test_path_error_message_mentions_format() {
        let err = validate_path("/only/two").unwrap_err();
        assert!(
            err.contains("4 segments"),
            "error should mention the expected shape, got: {err}"
        );
        assert!(
            err.contains("workspace"),
            "error should mention 'workspace', got: {err}"
        );
    }
```

- [ ] **Step 2: Run the new tests and verify they fail**

Run:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml \
  test_path_three_segments_rejected \
  test_path_five_segments_rejected \
  test_path_error_message_mentions_format
```

Expected: all three fail.
- `test_path_three_segments_rejected` fails because `/ns/dev/app` currently validates as 3 ≥ 2 → `Ok`, but `.is_err()` is expected.
- `test_path_five_segments_rejected` fails because `/ns/dev/app/KEY/EXTRA` currently validates as 5 ≥ 2 → `Ok`.
- `test_path_error_message_mentions_format` fails because the current error message is `"path must have at least 2 segments"` — doesn't contain `"4 segments"` or `"workspace"`.

- [ ] **Step 3: Update `validate_path` to the new rule**

In `flykeep-server/src/routes.rs`, find this block inside `validate_path`:

```rust
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.len() < 2 {
        return Err("path must have at least 2 segments".to_string());
    }
```

Replace those 4 lines with:

```rust
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.len() != 4 {
        return Err(
            "path must have exactly 4 segments: /workspace/project/env/key".to_string(),
        );
    }
```

Leave the surrounding code (leading slash check, trailing slash check, empty segment check, lowercasing at the end) untouched.

- [ ] **Step 4: Remove the obsolete `test_valid_path_two_segments` test**

Find and delete this test in the same `mod tests` block:

```rust
    #[test]
    fn test_valid_path_two_segments() {
        assert!(validate_path("/ns/KEY").is_ok());
    }
```

It asserts the opposite of what we now want — a 2-segment path should now be rejected. Keep `test_valid_path_four_segments` — it still passes with a 4-segment input.

- [ ] **Step 5: Run the full server test suite and verify everything passes**

Run:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml
```

Expected: all tests pass. Pay particular attention to:
- The 3 new tests (`test_path_three_segments_rejected`, `test_path_five_segments_rejected`, `test_path_error_message_mentions_format`) — all green.
- The existing `test_valid_path_four_segments` — still green.
- The existing `test_path_single_segment`, `test_path_empty`, `test_path_just_slash`, `test_path_no_leading_slash`, `test_path_trailing_slash`, `test_path_lowercased` — all still green (they either test other validation rules or use valid 4-segment inputs).
- The existing integration tests (`test_put_and_get_roundtrip`, `test_list_secrets`, `test_delete_existing`, etc.) — all use 4-segment paths (`/ns/dev/app/KEY`) and continue to pass.

If any unexpected test fails, investigate: it may be using a path shape that was permissive under the old rule but is now rejected. Fix the test input to a 4-segment equivalent (`/ns/dev/app/KEY`).

- [ ] **Step 6: Commit**

```bash
git add flykeep-server/src/routes.rs
git commit -m "$(cat <<'EOF'
feat: enforce exactly 4 segments in validate_path

Secret paths must now be /workspace/project/env/key — 3 or 5+
segments return 400 with an error message that names the expected
shape. Removes test_valid_path_two_segments; adds tests for 3-segment
rejection, 5-segment rejection, and error message content.
EOF
)"
```

---

## Task 2: Add startup path audit

**Files:**
- Modify: `flykeep-server/src/db.rs` — add `count_non_4_segment_paths` method + test
- Modify: `flykeep-server/src/main.rs` — call the audit after `Database::init` and log

This task is also TDD: a unit test for the new method drives its implementation, then we wire it into startup in `main.rs` (the wiring is trivial enough that it doesn't get its own test — we validate it by `cargo build`).

- [ ] **Step 1: Add the failing test for `count_non_4_segment_paths`**

Open `flykeep-server/src/db.rs` and locate the `mod tests` block at the bottom. Add this test after the existing `test_delete_nonexistent_returns_false`:

```rust
    #[test]
    fn test_count_non_4_segment_paths() {
        let (db, _dir) = temp_db();

        // Empty DB → 0 mismatches.
        assert_eq!(
            db.count_non_4_segment_paths().expect("test: count empty"),
            0
        );

        // A valid 4-segment path — should not be counted as mismatched.
        db.put_secret("/ns/dev/app/KEY", b"v1", b"nonce_ok_12by")
            .expect("test: put valid");
        assert_eq!(
            db.count_non_4_segment_paths().expect("test: count after valid"),
            0,
            "4-segment path should not be flagged"
        );

        // A 2-segment legacy path — bypasses validate_path (which lives in
        // routes.rs) by calling put_secret directly. Simulates data written
        // under the old rule.
        db.put_secret("/legacy/KEY", b"v2", b"nonce_legacy12")
            .expect("test: put 2-segment");
        assert_eq!(
            db.count_non_4_segment_paths().expect("test: count after 2-seg"),
            1,
            "2-segment legacy path should be flagged"
        );

        // A 5-segment path — also flagged.
        db.put_secret("/a/b/c/d/e", b"v3", b"nonce_5_seg12")
            .expect("test: put 5-segment");
        assert_eq!(
            db.count_non_4_segment_paths().expect("test: count after 5-seg"),
            2,
            "5-segment path should be flagged"
        );
    }
```

- [ ] **Step 2: Run the test and verify it fails to compile**

Run:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml test_count_non_4_segment_paths
```

Expected: compilation error — `no method named count_non_4_segment_paths found for struct Database`.

- [ ] **Step 3: Implement `count_non_4_segment_paths` on `Database`**

In `flykeep-server/src/db.rs`, add this method to the `impl Database` block. Put it after `delete_secret` and before the closing `}` of the impl block:

```rust
    /// Counts rows whose `path` does not have exactly 4 segments under the
    /// new grammar (/workspace/project/env/key). Used at startup to warn
    /// about legacy data that became unreachable after the path rule was
    /// tightened.
    ///
    /// Implementation: counts the number of '/' characters in each path
    /// (4 slashes = 4 segments, since a valid path starts with '/' and
    /// has no trailing '/'). A path like `/a/b/c/d` has exactly 4 slashes;
    /// `/a/b/c` has 3; `/a/b/c/d/e` has 5.
    pub fn count_non_4_segment_paths(&self) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock poisoned: {e}"))?;
        conn.query_row(
            "SELECT COUNT(*) FROM secrets
             WHERE (LENGTH(path) - LENGTH(REPLACE(path, '/', ''))) != 4",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| format!("count query failed: {e}"))
    }
```

- [ ] **Step 4: Run the test and verify it passes**

Run:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml test_count_non_4_segment_paths
```

Expected: PASS.

- [ ] **Step 5: Add the re-init preservation test**

The spec also calls for a test that seeds a legacy-shaped row, re-opens the DB via `Database::init`, and asserts the row is still present and still counted. Add this test immediately after `test_count_non_4_segment_paths` in the `mod tests` block:

```rust
    #[test]
    fn test_init_preserves_mismatched_paths() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().expect("test: path str");

        // First init — empty DB, no warnings would fire.
        let db = Database::init(db_path_str).expect("test: first init");

        // Seed a legacy 2-segment path by calling put_secret directly
        // (bypasses validate_path, which lives in routes.rs).
        db.put_secret("/legacy/KEY", b"legacy-value", b"nonce_legacy12")
            .expect("test: seed legacy row");

        // Drop the handle to release the SQLite lock before re-init.
        drop(db);

        // Second init on the same file — simulates a server restart.
        // Must not delete or rewrite existing rows.
        let db2 = Database::init(db_path_str).expect("test: re-init");

        // Legacy row still readable via get_secret.
        let row = db2
            .get_secret("/legacy/KEY")
            .expect("test: get after re-init")
            .expect("test: legacy row should still exist");
        assert_eq!(row.value, b"legacy-value");

        // Audit still flags the legacy row.
        assert_eq!(
            db2.count_non_4_segment_paths()
                .expect("test: count after re-init"),
            1,
            "legacy row should still be counted as mismatched after re-init"
        );
    }
```

Run the new test:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml test_init_preserves_mismatched_paths
```

Expected: PASS (nothing in `Database::init` deletes rows — the test verifies the current behavior and guards against future regressions).

Also run the full server test suite to confirm nothing else broke:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml
```

Expected: all tests pass, including Task 1's tests.

- [ ] **Step 6: Wire the audit into `main.rs`**

Open `flykeep-server/src/main.rs` and find the block that initializes the database:

```rust
    let database = Database::init(&db_path)
        .expect("startup: failed to initialize database");
    let state = Arc::new(AppState {
```

Insert the audit block between `Database::init(...)` and the `AppState` construction. The final shape of that region should be:

```rust
    let database = Database::init(&db_path)
        .expect("startup: failed to initialize database");
    match database.count_non_4_segment_paths() {
        Ok(0) => {}
        Ok(n) => eprintln!(
            "warning: {n} existing secrets have paths that don't match the new 4-segment grammar (/workspace/project/env/key); they will be unreachable via the API until recreated with a valid path"
        ),
        Err(e) => eprintln!("warning: path audit query failed: {e}"),
    }
    let state = Arc::new(AppState {
```

Notes:
- `database` is not yet wrapped in `Arc` at this point — calling `database.count_non_4_segment_paths()` works on the owned value before it's moved into `Arc::new` inside `AppState`.
- `Ok(0)` is an explicit no-op so the common case (clean DB) stays silent.
- `Err(...)` logs but does not abort startup. A broken audit query shouldn't keep the server from starting.

- [ ] **Step 7: Build the server to verify `main.rs` compiles cleanly**

Run:

```bash
cargo build --manifest-path flykeep-server/Cargo.toml
```

Expected: successful build with no warnings from `main.rs`. If the build fails with "value used after move" or similar, double-check that the audit block is **before** the `AppState { db: Arc::new(database), ... }` line, since that line moves `database` into the `Arc`.

- [ ] **Step 8: Run the full test suite one more time**

```bash
cargo test --manifest-path flykeep-server/Cargo.toml
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add flykeep-server/src/db.rs flykeep-server/src/main.rs
git commit -m "$(cat <<'EOF'
feat: warn at startup about paths that don't match 4-segment grammar

Adds Database::count_non_4_segment_paths, called from main.rs after
init. Operators see a single warning line listing the number of
legacy rows that are now unreachable via the API. No data is
modified — the rows stay in the DB until explicitly recreated.
EOF
)"
```

---

## Task 3: Update docs — PRD, README, CHANGELOG

**Files:**
- Modify: `prd.md` — Path Rules section + example paths throughout
- Modify: `README.md` — CLI usage and docker entrypoint examples
- Modify: `CHANGELOG.md` — add `[Unreleased]` section

No tests in this task — it's all documentation. One commit at the end.

- [ ] **Step 1: Update `prd.md` Path Rules section**

Open `prd.md` and find the "Path Rules" section (around line 43):

```markdown
### Path Rules

- Must start with `/`
- Format: `/namespace/environment/appname/KEY`
- Minimum 2 segments
- No trailing slash
- Case-sensitive
- Invalid paths return `400`
```

Replace that bullet list with:

```markdown
### Path Rules

- Must start with `/`
- Format: `/workspace/project/env/key` — exactly 4 segments
- No trailing slash
- Lowercased by the server
- Invalid paths return `400`
```

(Removed the "Minimum 2 segments" bullet, removed "Case-sensitive" which was incorrect anyway — the server lowercases — and tightened the format line.)

- [ ] **Step 2: Update `prd.md` example paths to the new convention**

Still in `prd.md`, update these example paths to match the new `workspace/project/env/key` ordering and vocabulary. Use `/acme/myapp/dev/DB_URL` and `/acme/myapp/dev/API_KEY` as the canonical examples throughout.

Find and replace (one at a time, since the contexts differ):

Line ~68 — GET example:
```
GET /secrets?path=/namespace/dev/myapp/DB_URL
```
Replace with:
```
GET /secrets?path=/acme/myapp/dev/DB_URL
```

Line ~71 — response body:
```
200: { "path": "/namespace/dev/myapp/DB_URL", "value": "plaintext" }
```
Replace with:
```
200: { "path": "/acme/myapp/dev/DB_URL", "value": "plaintext" }
```

Line ~76 — prefix list:
```
GET /secrets?prefix=/namespace/dev/
```
Replace with:
```
GET /secrets?prefix=/acme/myapp/
```

Line ~79 — prefix list response:
```
200: { "paths": ["/namespace/dev/myapp/DB_URL", "/namespace/dev/myapp/API_KEY"] }
```
Replace with:
```
200: { "paths": ["/acme/myapp/dev/DB_URL", "/acme/myapp/dev/API_KEY"] }
```

Line ~83 — SQL example:
```
Implemented as `SELECT path FROM secrets WHERE path LIKE '/namespace/dev/%'`.
```
Replace with:
```
Implemented as `SELECT path FROM secrets WHERE path LIKE '/acme/myapp/%'`.
```

Line ~89 — PUT body example:
```
Body: { "path": "/namespace/dev/myapp/DB_URL", "value": "plaintext" }
```
Replace with:
```
Body: { "path": "/acme/myapp/dev/DB_URL", "value": "plaintext" }
```

Line ~96 — DELETE example:
```
DELETE /secrets?path=/namespace/dev/myapp/DB_URL
```
Replace with:
```
DELETE /secrets?path=/acme/myapp/dev/DB_URL
```

Lines ~154–157 — CLI examples block:
```
flykeep get /namespace/dev/myapp/DB_URL
flykeep set /namespace/dev/myapp/DB_URL "value"
flykeep list /namespace/dev/
flykeep delete /namespace/dev/myapp/DB_URL
```
Replace with:
```
flykeep get /acme/myapp/dev/DB_URL
flykeep set /acme/myapp/dev/DB_URL "value"
flykeep list /acme/myapp/
flykeep delete /acme/myapp/dev/DB_URL
```

Note the ordering change: the original examples put `dev` (env) as segment 2 and `myapp` (project) as segment 3. Under the new convention the order is `workspace/project/env/key`, so `myapp` moves to segment 2 and `dev` moves to segment 3.

- [ ] **Step 3: Update `README.md` CLI usage examples**

Open `README.md` and find the "Usage" section around line 57. The current block looks like:

```
flykeep set /apps/myapp/db_url postgres://localhost
flykeep get /apps/myapp/db_url
flykeep list /apps/myapp/
flykeep list /apps/myapp/ --values
flykeep delete /apps/myapp/db_url
```

These are 3-segment examples (`apps/myapp/db_url`) that would be rejected by the new validator. Replace with:

```
flykeep set /acme/myapp/prod/DB_URL postgres://localhost
flykeep get /acme/myapp/prod/DB_URL
flykeep list /acme/myapp/prod/
flykeep list /acme/myapp/prod/ --values
flykeep delete /acme/myapp/prod/DB_URL
```

Then find the "Output formats" block around line 69:

```
flykeep list /apps/ --format table   # default, includes timestamps
flykeep list /apps/ --format env     # KEY=VALUE pairs (auto-fetches values)
flykeep list /apps/ --format json    # JSON array (auto-fetches values)
```

Replace with:

```
flykeep list /acme/myapp/ --format table   # default, includes timestamps
flykeep list /acme/myapp/ --format env     # KEY=VALUE pairs (auto-fetches values)
flykeep list /acme/myapp/ --format json    # JSON array (auto-fetches values)
```

Then find the "Docker Entrypoint" block around line 84:

```bash
export $(flykeep list /apps/myapp/prod/ --format env)
```

Replace with:

```bash
export $(flykeep list /acme/myapp/prod/ --format env)
```

- [ ] **Step 4: Add `[Unreleased]` section to `CHANGELOG.md`**

Open `CHANGELOG.md`. Current content:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-04-09

### Changed

- README updates
- `flykeep version` command returns server and client versions
- `/alive` endpoint now returns server version

## [0.1.0] - 2026-04-09

Initial release.
```

Insert a new `[Unreleased]` section directly under the intro line and above the `[0.2.0]` entry. The file should become:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- **Breaking:** secret paths now require exactly 4 segments:
  `/workspace/project/env/key`. Paths with fewer or more segments are
  rejected with `400`. Existing secrets stored under other shapes will
  remain in the database but become unreachable via the API until
  recreated with a valid path. The server logs a one-line warning at
  startup if any mismatched rows are present.

## [0.2.0] - 2026-04-09

### Changed

- README updates
- `flykeep version` command returns server and client versions
- `/alive` endpoint now returns server version

## [0.1.0] - 2026-04-09

Initial release.
```

- [ ] **Step 5: Verify the server still builds and tests still pass**

Documentation changes shouldn't break the build, but run it once for sanity:

```bash
cargo test --manifest-path flykeep-server/Cargo.toml
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add prd.md README.md CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs: align PRD, README, CHANGELOG with 4-segment path grammar

Updates the PRD's Path Rules section and every example path to the
new /workspace/project/env/key ordering. README CLI examples use
/acme/myapp/prod/DB_URL as the canonical 4-segment form. CHANGELOG
gains an [Unreleased] section describing the breaking change and
the startup warning.
EOF
)"
```

---

## Final verification

After Task 3 is committed, run the full test suite and a clean build one last time to confirm everything is green:

```bash
cargo build --manifest-path flykeep-server/Cargo.toml
cargo test --manifest-path flykeep-server/Cargo.toml
cargo build --manifest-path flykeep-cli/Cargo.toml
cargo test --manifest-path flykeep-cli/Cargo.toml
```

All four commands should succeed with zero warnings and all tests passing.

Then `git log --oneline -5` should show the three new commits on top of the previous `267c072` specs commit:

```
<sha> docs: align PRD, README, CHANGELOG with 4-segment path grammar
<sha> feat: warn at startup about paths that don't match 4-segment grammar
<sha> feat: enforce exactly 4 segments in validate_path
267c072 docs: add specs for 4-segment paths and multi-user/service accounts
```

The branch is then ready to either merge or tag for release.
