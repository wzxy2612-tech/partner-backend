# Partner Multi-Tenancy Backend

Backend foundation that lets approved channel partners onboard and manage their
own companies, workspaces, users, branding, workflows and usage, with
**database-enforced tenant isolation**. The existing direct-customer Stripe flow
is preserved untouched; partner-managed users bypass Stripe.

Built as a portfolio project. All five feature phases are complete, plus
ongoing audit-driven hardening rounds that close cross-tenant holes
the earlier audits surfaced.

> **Start here**: Read [The isolation design](#the-isolation-design-structural-not-behavioural) first to understand the security model in 20 minutes; the remaining sections provide detailed feature & audit evidence.

## The isolation design (structural, not behavioural)

A common approach scopes tenants in application code (`WHERE partner_id = ?` on
every query). It fails **open**: forget one filter and you leak another tenant's
data — and over time someone forgets.

Here the tenant boundary lives in PostgreSQL Row-Level Security (RLS). The
database is the single authority for "which rows belong to this tenant", so a
missing filter fails **closed** (you see nothing). Application code may add its
own scoping for ergonomics, but RLS is the backstop.

### Four database roles (privilege boundaries enforced by Postgres)

| role           | used for                                           | RLS                       |
|----------------|----------------------------------------------------|---------------------------|
| `app_owner`    | migrations / DDL only, never at request time       | subject (FORCE)           |
| `app_runtime`  | partner-facing request path                        | subject, **NOBYPASSRLS**  |
| `app_platform` | direct-customer / platform-admin / Stripe webhooks | **BYPASSRLS**             |
| `app_dispatcher` | outbox delivery — per-table `USING (true)` policies | subject (no BYPASSRLS) |

Partner requests can only ever run as `app_runtime`, which cannot see across
tenants no matter what the query says.

### Safe migration / backward compatibility

- New partner-owned tables (`partners`, `companies`, `memberships`,
  `partner_activity_log`, `sessions`, `workspaces`, `invitations`,
  `connectors`, `workflow_templates`, `workflows`, `token_usage`,
  `threads`, `outbox_events`): RLS **ENABLED and FORCED** → fail closed,
  even for the owner, even with no tenant context set.
- The pre-existing `users` table gains `partner_id` / `billing_source` with
  safe defaults (nil-sentinel partner + `stripe`) and RLS **ENABLED but not
  FORCED**, so the existing direct-customer + Stripe path (`app_platform`) is
  unchanged.

### Tenant scope comes from the server, never the client

`partner_id` is derived from the authenticated principal and applied with
`SET LOCAL` (transaction-scoped, pooling-safe). The client never supplies it.

### Row visibility ≠ referential integrity

RLS decides "may I see or write THIS row". It does not decide "is the row I
POINT AT mine". PostgreSQL deliberately exempts referential-integrity checks
from row security (so that constraints cannot be subverted by hiding rows).
That is correct in general, and it is exactly why every single-column FK was a
tenant hole: under partner A's RLS scope, inserting `workflows.company_id =
<company of B>` succeeds because the FK trigger looks up the parent row without
any tenant scope and finds it. The hardening round (Phase 6) closes every one
of those holes with composite tenant FKs and DB-side gate functions.

## Auth & lifecycle (Phase 2)

Authentication runs on the **platform path** because it must read the
session/user/partner rows *before* any tenant scope exists. It resolves a bearer
token to a `Principal`, and the principal's `partner_id` then decides which DB
path (and RLS scope) the request runs under.

- **Revocable sessions.** Tokens are opaque, high-entropy strings; only their
  SHA-256 hash is stored. The DB session row — not the token body — is the
  authority, so revocation is just an `UPDATE ... SET revoked_at`. No secret
  material to leak, and stateless-JWT's "can't revoke" problem doesn't arise.
- **Passwords** use stdlib PBKDF2-HMAC-SHA256 with per-password salts and
  constant-time verification (no bcrypt/passlib dependency).
- **Suspension / domain deactivation** each pair a state change with token
  revocation *in the same transaction*, so a partner can never be left
  suspended-but-still-logged-in. Suspension stamps the 60-day retention window.
- **Stripe-bypass** is one pure function — the single authority for "does this
  user bypass Stripe?" — and has a full truth-table test.
- **Scope inheritance:** a Partner Super Admin granted at partner scope reaches
  every company/workspace beneath it. The *rule* is pure and unit-tested; the
  ancestry walk runs under the caller's RLS scope, so it can only ever traverse
  the caller's own tree.
- **Workspaces** form a company-scoped parent/child tree and sit under the same
  ENABLE+FORCE RLS as the other partner tables.
- **Transactional outbox for email.** Invitation delivery is decoupled from the
  transaction: an `outbox_events` row is committed inside the SAVEPOINT, and the
  `app_dispatcher` service delivers the email only after the transaction commits. A
  failed row 2 no longer orphans row 1's email. Keys are configured via
  `OUTBOX_KEYS` (`version:hex` pairs, no default, no fallback); each row stores
  the `key_version` used, enabling rotation (old rows decrypt with the previous
  key, new rows encrypt with the current one).

## RBAC & onboarding (Phase 3)

**Server-side RBAC** is decided as two independent questions, kept separate so
neither can silently widen the other:

1. *Does this role grant this permission?* — a static `ROLE_PERMISSIONS` table
   (Partner Super Admin ⊇ Company Admin ⊇ Author ⊇ Read-Only).
2. *Does the grant's scope reach the target?* — the Phase 2 scope-inheritance
   walk.

A principal may act only where **both** hold. `enforce()` resolves the target's
scope chain *under the caller's RLS scope*, so a target in another tenant can't
even be named — RBAC is a second lock, not the only one. The pieces are pure and
unit-tested; `enforce()` wires them to the DB and raises 403.

**Two-step CSV onboarding:**

- *Validate* parses the CSV and returns per-row errors (bad email, unknown role,
  unknown company, duplicate-in-file, already-exists) and **writes nothing**.
- *Commit* re-validates, then inserts every user + membership + invitation for
  the whole batch inside a single `SAVEPOINT`. Any failure — including an email
  that collides across tenants, which RLS hides from validation — rolls the
  entire batch back. Never a half-onboarded partner.

**Invitations** close the loop with auth: an onboarded user starts inactive with
no password; redeeming the one-time token sets their password and activates them,
after which the Phase 2 login flow works. Delivery is behind a pluggable
`EmailSender` (configured via `OUTBOX_SENDER`; tests use `OutboxEmailSender` in memory).

**Email uniqueness.** `users.email` is globally unique (baseline schema UNIQUE
constraint). When onboarding collides, the SAVEPOINT rolls back and the
per-row error maps the unique-violation to a stable 409 response.

## Hardening round (Phase 6)

Fifteen migrations driven by external audits. Each closes one class of
cross-tenant hole that the earlier phases left open.

| Migration | Hole closed |
|-----------|-------------|
| **0007** composite tenant FKs | FK triggers bypass RLS — a row in A could point at B's row. Every FK now includes `partner_id` and is checked under the caller's RLS scope. |
| **0008** value constraints + grants | `token_usage` accepted negative counts and impossible periods; `app_runtime` had blanket DML on every table including direct-customer data. |
| **0009** platform tenant row | The nil UUID (platform/direct sentinel) had no row to reference — `users.partner_id` and `sessions.partner_id` were the only partner columns without an FK, allowing phantom partner IDs. |
| **0010** platform role integrity | A forged membership could grant `platform_super_admin` inside a partner's own RLS scope. Role insertion is now gated by the platform path. |
| **0011** RLS active-state gate | TOCTOU: identity resolved in one transaction, business operation in the next — a suspend could slip between. The `partners` policy now gates on `partner_is_active()`, which runs as `SECURITY INVOKER` under the caller's RLS scope (requiring explicit RLS policies for roles that evaluate it). |
| **0012** workspace parent same-company | A workspace could be reparented under a sibling workspace in the same partner but different company, causing scope inheritance to return the wrong company. |
| **0013** transactional outbox | Invitation emails were sent inside the batch SAVEPOINT — row 2 failure orphaned row 1's email. Outbox decouples delivery from the transaction. |
| **0014** outbox RLS + bookkeeping | The outbox table shipped with no tenant boundary; any tenant could read, rewrite, or delete another tenant's queued mail. RLS ENABLE + FORCE applied, plus a migration bookkeeping table. |
| **0015** billing gate function | `billing_contact_email` was the one column outside the write gate (REVOKE + GRANT workaround). A suspended partner's in-flight request could still update it. A DB-side gate function now makes the write decision inside PostgreSQL, closing the TOCTOU window entirely. |
| **0016** alembic_version grant cleanup | `ALTER DEFAULT PRIVILEGES` (db/init/00-roles.sql) left `alembic_version` granted to `app_platform` (BYPASSRLS), so the migration gate's evidence could be rewritten by the code it constrains. Revoked. |
| **0017** outbox terminal invariants | The `failed` state allowed a dead-lettered event to retain a recoverable ciphertext+nonce, and the application code chose whether to clear it. Now the state machine is enforced by three CHECK constraints: `pending` ↔ ciphertext+nonce present, `sent` ↔ ciphertext null, `failed` ↔ ciphertext null. |
| **0018** app_dispatcher role | A fourth role for outbox delivery. Given BYPASSRLS it would have the blast radius of `app_platform`; instead it gets three narrow per-table `USING (true)` policies, so its reach is opt-in and auditable per table. |
| **0019** runtime outbox INSERT-only | `app_runtime` previously had blanket DML on `outbox_events` (via default privileges). Now `app_runtime` can only INSERT (column-scoped to 8 columns with default pending/now values), making the queue append-only for runtime. |
| **0020** revoke default privileges | `db/init/00-roles.sql` no longer grants default privileges on future objects; `0020` revokes any that survived on already-initialized clusters. New tables are born unreachable; every grant must be explicit in the migration that creates the table. Includes `audit_default_privileges` single-predicate view and `PRIOR_STATE` downgrade reconstruction. |
| **0021** function EXECUTE grants | PostgreSQL grants `EXECUTE` on new functions to PUBLIC via a hardwired default (`proacl IS NULL`). This is root cause A in its second form: functions are reachable before anyone decides they should be. Revoked; explicit grants added. Includes the `DROP + CREATE` trap warning (CREATE OR REPLACE preserves ACL). |

## API overview

| Router | Prefix | Purpose |
|--------|--------|---------|
| `auth` | `/auth` | Login / logout (platform path) |
| `partners` | `/partners` | Partner lifecycle: suspend / activate / deactivate-domain, billing contact |
| `workspaces` | `/workspaces` | Company-scoped workspace tree (parent/child) |
| `onboarding` | `/onboarding` | Two-step CSV onboarding (validate + commit) |
| `invitations` | `/invitations` | Invite redemption (one-time token → password + activation) |
| `activity` | `/activity` | Keyset-paginated activity log with date/event filters |
| `branding` | `/branding` | Workspace and company branding inheritance |
| `workflows` | `/workflows` | Template cloning gated by connector verification |
| `usage` | `/usage` | Monthly per-partner token usage |
| `maintenance` | `/maintenance` | 60-day suspension purge + 1-year thread archival |

## Tests

Test counts are tracked by `verify_fixes.py` as the single source of truth (currently 220 collected tests across 37 test files via `make test`). The suite covers:

- **Tenant isolation** — visibility, write blocking, cross-tenant FK rejection
- **Cross-table reference ownership** — FK triggers cannot be used to point at
  another tenant's row (composite FKs + RLS interaction)
- **RLS coverage** — every partner-owned table verified under RLS
- **TOCTOU races** — suspend/deactivate vs invitation redemption, with real
  lock contention (`wait_event_type = 'Lock'`) asserted; reverse-order
  (redemption before deactivation) also covered
- **Lifecycle gates** — suspended partner cannot update billing, deactivated
  domain cannot receive invitations
- **Outbox isolation** — each tenant's queued mail is invisible to other tenants
- **Outbox crypto** — key configuration (OUTBOX_KEYS, no default), duplicate
  version rejection, rotation reachability; provider error bodies never
  stored in last_error (type-only)
- **Dispatcher sender gates** — no default sender; OUTBOX_SENDER must name a
  registered delivering sender; console deliberately absent from registry;
  refusal happens before create_engine (exit 1)
- **Default privileges / function grants** — new tables and functions born
  unreachable; audit_default_privileges single predicate; function EXECUTE
  default (proacl NULL) revoked
- **Platform role integrity** — forged membership cannot grant platform roles
- **Scope inheritance** — Partner Super Admin reaches the full subtree;
  Company Admin is bounded to its own company
- **Password hashing** — PBKDF2-HMAC-SHA256 with constant-time verification

## Run it

```bash
make up      # postgres + auto-migrate + api on :8000
make test    # tenant-isolation suite (see verify_fixes.py for exact count)
make migrate # run alembic migrations
make logs    # tail the API container
```

The dispatcher is a one-shot worker — invoke it directly:

```bash
docker compose run --rm --build dispatcher
```

`make dispatch` is a dev convenience; the exit-code contract holds for
the process, not for the `make` wrapper.

### Local dev: decode a queued invitation token

The outbox has no delivering sender, so no invitation mail is produced
locally. `tools/dev/dev_decode_invite_token.py` decrypts queued tokens for
building the activation page. It is a decryption oracle, so it must be
named, with no default:

```bash
ALLOW_TOKEN_DECRYPT=i-understand \
docker compose exec -T -e ALLOW_TOKEN_DECRYPT -e PYTHONPATH=/app api \
    python3 tools/dev/dev_decode_invite_token.py
```

Truthiness is not consent: only the exact phrase runs it. CORS
(`CORS_ALLOW_ORIGINS`) is off by default; set it to a comma-separated
literal list of origins — a wildcard is refused.

Or manually:

```bash
docker compose up -d --build
docker compose exec api pytest
```

### Verification tools

- `verify_fixes.py` — validates that each audit item's fix is present in the
  codebase and that the test count matches expectations. Run after any round of
  fixes to confirm nothing was missed.
- `check_container_sync.sh` — checks that the running container state matches
  the expected Docker configuration.

## Roadmap

- **Phase 1 (done):** schema, RLS isolation core, isolation tests.
- **Phase 2 (done):** revocable sessions + server-resolved principal, partner
  activation/suspension (+ cascade token revocation), domain deactivation,
  workspace parent/child tree, scope-inheritance rule, Stripe-bypass decision.
- **Phase 3 (done):** server-side RBAC (role × scope) on mutations, two-step
  transactional CSV onboarding, invitation redemption.
- **Phase 4 (done):** activity-log API (keyset pagination + date/event filters),
  parent-hub branding inheritance, billing-contact controls.
- **Phase 5 (done):** workflow-template cloning gated by connector verification,
  monthly token-usage tracking, 60-day suspension purge + 1-year thread archival.
- **Phase 6 (done):** audit-driven hardening — composite tenant FKs, value
  constraints, platform tenant materialization, role integrity, RLS active-state
  gate, workspace parent same-company, transactional outbox, billing gate function,
  alembic_version grant cleanup (0016), outbox terminal invariants (0017),
  app_dispatcher role (0018), runtime outbox INSERT-only (0019), revoke default
  privileges (0020), function EXECUTE grants (0021).

**Next:** production deployment (containerized, multi-instance), observability
(metrics / tracing), rate limiting, per-partner email uniqueness, SMTP email
delivery (requires registering a delivering sender in
`DELIVERING_SENDERS`).

## Known limitations

- **No delivering sender configured.** `DELIVERING_SENDERS` is empty in this build; `OUTBOX_SENDER` must name a registered provider, and `ConsoleEmailSender` is deliberately not registerable (it would drain the queue into stdout and destroy every token). Registering an SMTP or provider sender is the one change that makes the dispatcher runnable.
- **Implicit delivery assertion (`provider_message_id` is an unpopulated slot).** The outbox considers an event `sent` as long as `send_invitation()` returns without raising, rather than recording a provider delivery receipt ID. `outbox_events.provider_message_id` exists in the schema (0013) but is not yet written at dispatch time.
- **No CI pipeline.** Automated tests and `verify_fixes.py` are executed locally or inside containers (`make test`), but no GitHub Actions / CI workflow is configured yet.
- **Dependencies declare lower bounds only.** `requirements.txt` has no lock file and no hashes; a fresh build may pull newer versions (mako already dragged in a top-level `tools` package that collides with the project's own `tools/` directory — worked around via `PYTHONPATH`). Reproducible builds and supply-chain verification are deferred to the CI stage.
- **No rate limiting.** API requests are unbounded; add a middleware or gateway layer before production exposure.
- **Single-instance design.** The current `docker compose` setup runs one API
  replica; horizontal scaling requires a shared session store and connection
  pooler.
- **CSV onboarding is Partner-Super-Admin only.** Company-scoped self-service
  onboarding is not wired yet.
- **Global email uniqueness.** `users.email` is globally unique (baseline
  schema). Cross-partner collisions are handled gracefully (409 on commit), but
  per-partner uniqueness would require a migration.
