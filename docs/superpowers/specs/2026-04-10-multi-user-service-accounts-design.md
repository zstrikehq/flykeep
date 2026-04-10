# flykeep — Multi-User / Service Accounts Design Spec

## Overview

Introduce per-account identities with scoped access, managed via CLI and enforced via Cedar policies. Replaces the two-global-token model with opaque account tokens stored in SQLite, plus grants expressed as Cedar boolean expressions over the 4-segment path grammar.

**Depends on**: [`2026-04-10-enforce-4-segment-paths-design.md`](./2026-04-10-enforce-4-segment-paths-design.md). The 4-segment path grammar must be in place before this work lands — Cedar policies reference individual segments as structured entity attributes.

---

## Motivation

Today flykeep has two global tokens: `FLYKEEP_ADMIN_TOKEN` (full access) and `FLYKEEP_READ_TOKEN` (read-only). Every caller shares the same credentials. There is no way to:

- Give one service access to just its own secrets.
- Revoke a single consumer without rotating everything.
- Let different humans or services have different permissions.
- Establish a foundation for future audit work.

Account-based access with Cedar-backed scoping addresses all four, while keeping the root env token around as a bootstrap and break-glass credential.

---

## Model

### Principals

- **Root** — authenticated by `FLYKEEP_ADMIN_TOKEN` (env var). Full access. Never goes through Cedar. Only credential that can manage accounts and grants.
- **Account** — authenticated by an opaque token looked up by SHA-256 hash in the `accounts` table. Access determined entirely by Cedar grants attached to the account. Cannot manage accounts or grants in v1.

### Resources

The Cedar `Secret` entity carries the 4 path segments as structured string attributes. The entity UID is the full path (human-readable in logs and traces); policies reference the attributes directly.

### Actions

Four: `Read`, `Write`, `Delete`, `List`. `List` is independent of `Read` — an account can have list-only permission (auditor pattern), read-only on a specific path with no discovery, or both.

---

## Cedar Schema

```cedar
entity Account;
entity Secret = {
  workspace: String,
  project:   String,
  env:       String,
  key:       String
};

action Read, Write, Delete, List
  appliesTo {
    principal: [Account],
    resource: [Secret]
  };
```

- `Account` has no attributes in v1. Adding `kind: String` later is a non-breaking schema change (existing policies don't reference it).
- `Secret` has exactly the 4 path fields. Cedar's strict validator rejects any expression referencing other attributes — this is how grant expression validation is enforced (no hand-rolled AST walker; see **Grant Validation**).
- No `context`. All authorization decisions are pure functions of `(principal, action, resource)`.

---

## Auth Model

| Credential | Scope | Revocation |
|---|---|---|
| `FLYKEEP_ADMIN_TOKEN` (env var) | Root bypass — allow-all, Cedar-skipped. Only credential that can manage accounts and grants. | Restart with a new env var |
| Account token (`fk_<base64url>`) | Whatever Cedar grants say. Cannot manage accounts. | `flykeep account delete / disable / rotate-token` — instant |

**`FLYKEEP_READ_TOKEN` is removed** (breaking). Existing deployments relying on read-only access migrate to creating an account with `read,list` grants.

### Deny codes

| Condition | Status |
|---|---|
| No `Authorization` header | `403` |
| Malformed header | `401` |
| Valid header, unknown token | `401` |
| Valid token, account disabled | `401` |
| `GET /secrets?path=X` with no matching `Read` grant | `404` (hide existence) |
| `GET /secrets?prefix=Y` — no prefix-level check | `200` (possibly empty after per-row filter) |
| `PUT /secrets` with no matching `Write` grant | `403` |
| `DELETE /secrets?path=X` with no matching `Delete` grant | `403` |
| Account calling any `/accounts*` endpoint | `403` |

---

## Data Model

Two new tables. The existing `secrets` table is unchanged.

```sql
CREATE TABLE IF NOT EXISTS accounts (
  id          TEXT PRIMARY KEY,       -- slug, ^[a-z0-9][a-z0-9-]{1,62}$
  kind        TEXT NOT NULL,           -- "user" | "service"
  name        TEXT NOT NULL,           -- human label, freeform
  token_hash  BLOB NOT NULL UNIQUE,    -- sha256(plaintext), 32 bytes
  created_at  INTEGER NOT NULL,
  disabled_at INTEGER                  -- NULL when enabled
);
CREATE INDEX IF NOT EXISTS idx_accounts_token_hash ON accounts(token_hash);

CREATE TABLE IF NOT EXISTS grants (
  id          TEXT PRIMARY KEY,        -- e.g. "svc-api-read-a1b2c3"
  account_id  TEXT NOT NULL,
  action      TEXT NOT NULL,            -- "read" | "write" | "delete" | "list"
  expr        TEXT NOT NULL,            -- Cedar boolean expression
  created_at  INTEGER NOT NULL,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_grants_account ON grants(account_id);
```

### Field notes

- **`accounts.id`** is the slug used as the Cedar `Account::"<id>"` entity UID. Validation: `^[a-z0-9][a-z0-9-]{1,62}$`. Cannot be changed once created.
- **`accounts.kind`** is metadata only in v1 (for human display in `flykeep account list`). Not exposed in Cedar. Valid values: `user`, `service`. Anything else is rejected at insert.
- **`token_hash`** is SHA-256 of the plaintext token. The plaintext is generated by the server, returned to the caller exactly once (on create and on rotate), and never persisted. The unique constraint catches the vanishingly-unlikely collision.
- **`grants.action`** enum: `read`, `write`, `delete`, `list`. Anything else is rejected at insert.
- **`grants.expr`** is a Cedar boolean expression over `resource.{workspace,project,env,key}`. Validated at insert time via Cedar's strict schema validator (see **Grant Validation**). Max length 2 KB.
- **`grants.id`** is generated as `<account_id>-<action>-<6 hex chars from CSPRNG>` on insert.
- **`ON DELETE CASCADE`** on `grants.account_id` ensures grants are cleaned up with their account.

---

## Token Format

```
fk_<43 chars of base64url, no padding>
```

Generation:

```rust
use rand::RngCore;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

let mut bytes = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut bytes);
let token = format!("fk_{}", URL_SAFE_NO_PAD.encode(bytes));
```

- `fk_` prefix makes tokens identifiable by secret scanners (GitHub, TruffleHog, GitLeaks).
- 32 bytes of CSPRNG entropy → 256 bits.
- base64url without padding for URL and header safety.
- Total length: 46 characters.

### Verification on incoming requests

1. Constant-time compare against the root env token first. If match → `Principal::Root`.
2. Otherwise, SHA-256 the incoming token and look up in `accounts` by `token_hash` (indexed, O(log n)).
3. If found and `disabled_at IS NULL` → `Principal::Account(row)`.
4. If found but disabled, or not found at all → `401`.

---

## Grant Validation

No hand-rolled AST walker. Validation uses Cedar's own strict validator against the schema:

```rust
pub fn validate_grant_expr(
    schema: &cedar_policy::Schema,
    action: &str,
    expr: &str,
) -> Result<(), String> {
    if expr.len() > 2048 {
        return Err("expression too long (max 2048 bytes)".to_string());
    }
    let policy_src = format!(
        "permit(principal == Account::\"v\", action == Action::\"{action}\", \
         resource) when {{ {expr} }};"
    );
    let policy = cedar_policy::Policy::parse(None, &policy_src)
        .map_err(|e| format!("parse error: {e}"))?;
    let set = cedar_policy::PolicySet::from_policies([policy])
        .map_err(|e| format!("policy set error: {e}"))?;
    let result = cedar_policy::Validator::new(schema.clone())
        .validate(&set, cedar_policy::ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        let msgs: Vec<String> =
            result.validation_errors().map(|e| e.to_string()).collect();
        Err(format!("invalid expression: {}", msgs.join("; ")))
    }
}
```

Because the schema is minimal (`Account` with no attributes, `Secret` with only 4 strings, no context), strict validation rejects:

- `resource.path` — no such attribute
- `resource.foo` — no such attribute
- `principal.kind` — `Account` has no attributes
- `context.*` — context is empty
- `Account::"other"`, or any entity reference outside the schema
- Function calls like `ip()`, `decimal()`
- Non-string literals or comparisons requiring them
- `has` / `is` / `in` expressions over fields that don't support them

And accepts:

- `resource.workspace`, `resource.project`, `resource.env`, `resource.key`
- `==`, `!=`, `like` (with `*` wildcards)
- `&&`, `||`, `!`
- `(...)` grouping
- String literals

The 2 KB length guard runs before parsing to reject trivially oversized payloads.

---

## Policy Cache

The per-account `PolicySet` is cached in memory to avoid rebuilding it on every request.

```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub encryption_key: [u8; 32],
    pub admin_token: String,
    // new:
    pub schema: Arc<cedar_policy::Schema>,
    pub authorizer: Arc<cedar_policy::Authorizer>,
    pub policy_cache:
        Arc<parking_lot::RwLock<HashMap<String, Arc<cedar_policy::PolicySet>>>>,
}
```

### Read path (hot)

```rust
fn policy_set_for(
    &self,
    account_id: &str,
) -> Result<Arc<cedar_policy::PolicySet>, AuthzError> {
    // fast path
    if let Some(ps) = self.policy_cache.read().get(account_id) {
        return Ok(ps.clone());
    }
    // slow path: build outside the write lock
    let ps = Arc::new(self.build_policy_set_from_db(account_id)?);
    self.policy_cache
        .write()
        .entry(account_id.to_string())
        .or_insert_with(|| ps.clone());
    Ok(ps)
}
```

- Sync `parking_lot::RwLock` — never held across `.await`.
- `PolicySet` is wrapped in `Arc` so reads clone cheaply.
- Build-on-miss can race for the same account (two concurrent first requests). Both build identical sets; `or_insert_with` retains one. Wasted work is harmless and minor.

### Invalidation

```rust
fn invalidate(&self, account_id: &str) {
    self.policy_cache.write().remove(account_id);
}
```

Called from:

- `POST /accounts/{id}/grants`
- `DELETE /accounts/{id}/grants/{grant_id}`
- `DELETE /accounts/{id}` (no-op on already-missing key)
- `POST /accounts/{id}/disable` and `.../enable` (belt-and-suspenders; doesn't strictly affect policies today)

**Not** called on `POST /accounts/{id}/rotate-token` — a token change doesn't affect the policy set for that account.

### Memory bound

Unbounded `HashMap`. At flykeep scale (tens to low hundreds of accounts), each `PolicySet` is a few KB. No LRU needed.

### Correctness

Mutation sequence: (1) DB write, (2) cache invalidation, (3) response. Any subsequent request sees the new state (cache miss → rebuild from DB). A request in flight with an old `Arc<PolicySet>` finishes under the old policies — acceptable read-your-writes semantics for a config-change operation.

---

## Authorization Flow

### Single-item actions (`Read`, `Write`, `Delete`)

```
GET /secrets?path=X  |  PUT /secrets  |  DELETE /secrets?path=X
  │
  ├─ auth middleware → Principal (Root or Account)
  │
  ├─ if Root → proceed unconditionally
  │
  ├─ parse path → (workspace, project, env, key)
  ├─ build resource entity:
  │    Secret::"<path>" { workspace, project, env, key }
  │
  ├─ build Cedar Request(principal, action, resource, Context::empty())
  │
  ├─ authorizer.is_authorized(&req, &policy_set, &entities)
  │
  ├─ Allow → proceed
  ├─ Deny → 404 (GET) or 403 (PUT / DELETE)
```

### List with per-row filtering

```
GET /secrets?prefix=Y
  │
  ├─ auth middleware → Principal
  │
  ├─ if Root → enumerate + return everything unfiltered
  │
  ├─ spawn_blocking:
  │    ├─ db.list_secrets(prefix)              (existing code)
  │    └─ rows.into_par_iter()                 (rayon)
  │         .filter(|row| cedar_list_check(row) == Allow)
  │         .collect()
  │
  ├─ return { "secrets": [filtered...] }       (200, possibly empty)
```

- No prefix-level Cedar check. Users can query any prefix and get back whatever their list grants permit. Empty filtered sets are normal `200` responses with `{"secrets": []}`.
- `PolicySet` and `Authorizer` are cloned as `Arc`s before entering the `spawn_blocking` closure. Both are `Send + Sync`.
- `Entities` is built per row (each row has a distinct resource entity with its own 4 attrs).
- Rayon lives inside `spawn_blocking`, so both the DB read and the Cedar filtering are off the tokio runtime.

---

## HTTP API

### New endpoints — all require `Principal::Root`

Account tokens calling any of these get `403`.

#### Accounts

| Method | Path | Body | Response |
|---|---|---|---|
| `POST` | `/accounts` | `{"id":"svc-api","kind":"service","name":"API service"}` | `{"id":"svc-api","token":"fk_…","created_at":…}` — **token shown once** |
| `GET` | `/accounts` | — | `{"accounts":[…]}` |
| `GET` | `/accounts/{id}` | — | single account (no token) |
| `DELETE` | `/accounts/{id}` | — | `{"ok":true}` (cascades grants, invalidates cache) |
| `POST` | `/accounts/{id}/disable` | — | `{"ok":true}` |
| `POST` | `/accounts/{id}/enable` | — | `{"ok":true}` |
| `POST` | `/accounts/{id}/rotate-token` | — | `{"token":"fk_…"}` — old hash replaced atomically |

#### Grants

| Method | Path | Body | Response |
|---|---|---|---|
| `POST` | `/accounts/{id}/grants` | `{"action":"read","expr":"resource.workspace == \"acme\""}` | `{"id":"svc-api-read-a1b2","action":"read","expr":"…","created_at":…}` |
| `GET` | `/accounts/{id}/grants` | — | `{"grants":[…]}` |
| `DELETE` | `/accounts/{id}/grants/{grant_id}` | — | `{"ok":true}` |

### Existing endpoint updates

#### `GET /auth/verify`

Response now distinguishes root from account callers:

**Before**
```json
{"ok": true, "role": "admin"}
```

**After**
```json
// root token
{"ok": true, "principal": "root"}

// account token
{
  "ok": true,
  "principal": "account",
  "account": {"id": "svc-api", "kind": "service", "name": "API service"}
}
```

#### `GET /secrets?path=X` (single)

- Behavior unchanged on success.
- On authz deny: returns `404` with `{"error":"not found"}` — indistinguishable from a genuinely missing path. This is a deliberate information-hiding choice for reads.

#### `PUT /secrets`, `DELETE /secrets?path=X`

- On authz deny: returns `403`. The caller clearly already knows the path exists, so hiding existence would be pointless.

#### `GET /secrets?prefix=Y`

- Response shape unchanged: `{"secrets":[{path, created_at, updated_at}, ...]}`
- Rows that don't pass the per-row `List` check are silently filtered out. Empty results return `200 {"secrets":[]}`.

---

## CLI

### Config — unchanged

Single token in `~/.config/flykeep/config.toml` (and `FLYKEEP_TOKEN` env var). Role is discovered at call time by the server — commands that need root and are called with a non-root token get `403`. No "profiles" feature in v1.

### New commands

```sh
# Account lifecycle (requires root token)
flykeep account create <id> --kind user|service --name "Human Name"
flykeep account list
flykeep account show <id>
flykeep account disable <id>
flykeep account enable <id>
flykeep account delete <id>
flykeep account rotate-token <id>

# Grants — positional patterns (requires root token)
flykeep account grant <id> <action>[,<action>...] <path-pattern>...
flykeep account grant svc-api read  /acme/billing/prod/*
flykeep account grant svc-api read,list /acme/billing/*/*
flykeep account grant svc-api write /acme/billing/dev/*
flykeep account grant svc-api delete /acme/billing/dev/*

# Grants — --expr escape hatch for && / ! / cross-field conditions
flykeep account grant svc-api read \
  --expr 'resource.workspace == "acme" && !(resource.env == "prod")'

# Grant management
flykeep account grants <id>
flykeep account revoke-grant <id> <grant-id>
```

### Positional pattern translation

The CLI splits each positional pattern into exactly 4 slash-separated segments and emits equality constraints for each non-`*` segment:

| Positional | Generated `expr` |
|---|---|
| `/acme/billing/prod/DB_URL` | `resource.workspace == "acme" && resource.project == "billing" && resource.env == "prod" && resource.key == "DB_URL"` |
| `/acme/billing/prod/*` | `resource.workspace == "acme" && resource.project == "billing" && resource.env == "prod"` |
| `/acme/*/prod/*` | `resource.workspace == "acme" && resource.env == "prod"` |
| `/acme/billing/*/*` | `resource.workspace == "acme" && resource.project == "billing"` |

Multiple positional patterns are OR-joined:

```sh
flykeep account grant svc-api read /acme/billing/prod/* /acme/billing/stage/*
# → (resource.workspace=="acme" && resource.project=="billing" && resource.env=="prod")
#   || (resource.workspace=="acme" && resource.project=="billing" && resource.env=="stage")
```

### Positional guards

- Exactly 4 slash-separated segments.
- Each segment is either concrete text or `*` alone (no partial wildcards like `foo*` in positional form — use `--expr` for that).
- The all-`*` form `/*/*/*/*` is **rejected** to prevent accidental grant-everything. Users who really want allow-all use `--expr 'true'` explicitly.
- The server re-validates the generated `expr` via Cedar's strict validator — the CLI is not trusted.

### Multi-action shorthand

`grant svc-api read,list /...` creates **one grant row per action** atomically inside a single transaction. Revocation is still per-row (each action gets its own grant id).

### Example session

```
$ flykeep account create svc-api --kind service --name "Billing API service"
created svc-api
token: fk_3xK9pLm2Qn7VrT4hB6jY8sZ1cA5fD0gExJ7KlQ8M
save this now — it will not be shown again

$ flykeep account grant svc-api read,list /acme/billing/prod/*
granted: svc-api-read-a1b2c3 (read)
granted: svc-api-list-d4e5f6 (list)

$ flykeep account grants svc-api
ID                    ACTION  EXPRESSION
svc-api-read-a1b2c3   read    resource.workspace == "acme" && resource.project == "billing" && resource.env == "prod"
svc-api-list-d4e5f6   list    resource.workspace == "acme" && resource.project == "billing" && resource.env == "prod"

$ flykeep account rotate-token svc-api
new token: fk_9pXm3nQ7kL2vR8tY4hB6jZ1cA5fD0gEhJ6KlR7N
old token is now invalid
```

### Output format

All new commands honor the existing `--format table|env|json` global flag (default `table`). `env` format is not meaningful for account/grant commands — they fall back to `table` with a stderr note.

---

## Server Module Layout

```
flykeep-server/src/
  main.rs       - wiring, AppState (adds schema/authorizer/cache), startup
  crypto.rs     - unchanged
  db.rs         - Database init + migration + secrets CRUD (surface unchanged)
  accounts.rs   - NEW. Account + Grant types, DB ops, id/kind/action validation
  auth.rs       - REWRITTEN. Token hashing, SHA-256 lookup, Principal enum, middleware
  authz.rs      - NEW. Cedar schema, validator, policy cache, per-request check helpers
  routes.rs     - UPDATED. Existing /secrets handlers + /accounts, /accounts/*/grants
```

### Module boundaries

- **`auth.rs`** — "who is this caller?" Token parsing, hash lookup, root bypass. Produces a `Principal` enum. Zero knowledge of Cedar.
- **`authz.rs`** — "can this principal do this thing?" Schema, authorizer, cache, grant-expr validator. Zero knowledge of HTTP.
- **`accounts.rs`** — data types and DB operations for the `accounts` and `grants` tables. Validates `id`, `kind`, and `action` fields. Zero knowledge of Cedar or HTTP.
- **`routes.rs`** — wires the above into handlers. The only module that knows all three layers. The grant insert handler calls `authz::validate_grant_expr` before calling `accounts::insert_grant`, keeping Cedar out of `accounts.rs`.

---

## Config Changes

| Env Var | Change |
|---|---|
| `FLYKEEP_ENCRYPTION_KEY` | unchanged, required |
| `FLYKEEP_ADMIN_TOKEN` | unchanged, required — remains root bypass |
| `FLYKEEP_READ_TOKEN` | **REMOVED** (breaking) |
| `FLYKEEP_DB_PATH` | unchanged |
| `FLYKEEP_PORT` | unchanged |

`load_config()` drops the `read_token` field. If `FLYKEEP_READ_TOKEN` is still set in the environment after the upgrade, it is silently ignored — no warning, no error.

`AppState` changes:

- **Drop** `read_token: String`.
- **Add** `schema: Arc<Schema>` (built once at startup from a static string).
- **Add** `authorizer: Arc<Authorizer>` (built once at startup).
- **Add** `policy_cache: Arc<RwLock<HashMap<String, Arc<PolicySet>>>>`.

---

## Migration

No migration framework. `Database::init()` runs `CREATE TABLE IF NOT EXISTS` for the two new tables. The existing `secrets` table is untouched.

Upgrade path for deployed instances:

1. Deploy new binary.
2. `init()` creates empty `accounts` and `grants` tables.
3. `FLYKEEP_ADMIN_TOKEN` continues to work as root bypass immediately.
4. `FLYKEEP_READ_TOKEN`, if still set, is ignored.
5. Operators create accounts at their leisure: `flykeep account create …`.
6. Once all read-only clients have switched to account tokens, the `FLYKEEP_READ_TOKEN` env var can be removed from deployment config.

---

## Dependencies (server)

Add to `flykeep-server/Cargo.toml`:

```toml
cedar-policy = "4"
rayon        = "1"
parking_lot  = "0.12"
sha2         = "0.10"
base64       = "0.22"
rand         = "0.8"
```

No new CLI dependencies — the new subcommands use the existing `reqwest`, `clap`, `comfy-table`, and `serde_json`.

---

## CHANGELOG

Under `[Unreleased]` (appending to whatever entries the 4-segment paths spec adds):

```
### Added

- Multi-user / service accounts with opaque, DB-backed tokens managed via
  `flykeep account` commands.
- Cedar-based scoped access control with per-grant boolean expressions over
  `resource.{workspace,project,env,key}`.
- `flykeep account grant / revoke-grant / grants` for managing per-account
  permissions. Positional `/a/b/c/*` patterns or `--expr` for full Cedar
  expressions.
- `flykeep account disable / enable / rotate-token` for account lifecycle.

### Changed

- **Breaking:** `FLYKEEP_READ_TOKEN` env var removed. Migrate read-only
  clients to account tokens: create a service account, grant `read,list`
  on the relevant paths, and distribute the returned token.
- `GET /auth/verify` response now includes principal context (`root` or
  `account`) and drops the legacy `role` field.
- `GET /secrets?path=X` returns `404` when the caller has no matching read
  grant — indistinguishable from a genuinely missing path. This
  information-hiding behavior is new; the previous model had no read-deny
  case because every valid token (admin or read) permitted reads. `PUT`
  and `DELETE` continue to return `403` on authz denial.
```

---

## Tests

### Removed from existing suite

- `test_read_token_can_get`
- `test_read_token_cannot_put`
- `test_read_token_cannot_delete`
- `test_valid_read_token`
- `test_read_token_is_readonly_not_admin`

### `auth.rs`

- Root token → `Principal::Root`.
- Valid account token → `Principal::Account` with correct id / kind / name.
- Unknown token → `401`.
- Disabled account token → `401`.
- Malformed header (no `Bearer`, empty, etc.) → `401` / `403`.
- SHA-256 lookup miss returns `None` (sanity test).

### `accounts.rs`

- Create / list / show / delete roundtrip.
- FK cascade deletes grants when account deleted.
- Unique `token_hash` rejects duplicate inserts.
- `id` validation: valid slugs accepted; invalid (uppercase, starts with hyphen, too long, empty, special chars) rejected.
- `kind` validation: only `user` / `service`.
- Grant insert / list / delete.

### `authz.rs`

- `validate_grant_expr` accepts: single `==`, `like` with `*`, `&&`, `||`, `!`, multi-field compounds.
- `validate_grant_expr` rejects: `resource.path`, `resource.foo`, `principal.kind`, `context.x`, `Account::"other"`, function calls (`ip(...)`), oversize (>2048).
- Simple permit: grant `resource.env == "prod"` + request on prod secret → Allow.
- Simple deny: same grant + request on dev secret → Deny.
- Compound: `&&` with exclusion → behaves as expected.
- Policy cache: hit on second request without DB roundtrip, invalidate rebuilds on next call.
- Per-row list filter drops denied rows.

### `routes.rs` (integration-ish via `TestClient`)

- `POST /accounts` with root → 200, token returned once.
- `POST /accounts` with account token → 403.
- `PUT /secrets` with matching write grant → 200.
- `PUT /secrets` without grant → 403.
- `GET /secrets?path=X` with matching read grant → 200 with value.
- `GET /secrets?path=X` without grant → 404.
- `GET /secrets?prefix=Y` returns only items matching the caller's list grant.
- **Auditor pattern**: list-only account sees path list; individual `GET ?path=…` on any of those paths returns `404`.
- **Targeted pattern**: single-path read account with no list → list returns `[]`, specific path `GET` returns value.
- `POST /accounts/{id}/rotate-token` → old token gets `401` on next call.

### `flykeep-cli` (`wiremock`-based)

- `account create` prints token once, exits 0.
- `account grant` with positional patterns posts correctly generated `expr`.
- `account grant --expr` passes user input through verbatim.
- `account grant read,list …` makes two POSTs, one per action.
- `account grants` table output contains expected columns.
- All-`*` positional pattern is rejected client-side with a clear error.

---

## Out of Scope (v1)

- Audit log of who did what.
- Per-account management permission — only root can manage accounts and grants. A future Cedar `ManageAccounts` action can delegate this if needed.
- `principal.kind` or other Cedar attribute references — the `Account` schema has no attributes in v1.
- Middle-segment wildcards in positional shortcuts (`/acme/*/prod/*` works for whole-segment wildcards; partial-segment wildcards like `/acme/bill*/prod/*` are not supported — use `--expr` with `like`).
- Per-secret regions or multi-region deployment coordination (explicitly deferred; path stays 4 segments).
- Token expiry / TTL — tokens live until rotated or revoked.
- OAuth, SSO, or MFA.
- Self-service password or token reset.
- Policy templates or reusable policy components.
- CLI profiles for juggling multiple tokens (single-token config only).
- Non-root accounts managing other accounts.
