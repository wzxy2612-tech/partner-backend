# Partner Multi-Tenancy Backend

Backend foundation that lets approved channel partners onboard and manage their
own companies, workspaces, users, branding, workflows and usage, with
**database-enforced tenant isolation**. The existing direct-customer Stripe flow
is preserved untouched; partner-managed users bypass Stripe.

Built as a portfolio project. Phase 1 (this cut) delivers the part that is
genuinely hard to do well: provable cross-tenant isolation.

## The isolation design (structural, not behavioural)

A common approach scopes tenants in application code (`WHERE partner_id = ?` on
every query). It fails **open**: forget one filter and you leak another tenant's
data — and over time someone forgets.

Here the tenant boundary lives in PostgreSQL Row-Level Security (RLS). The
database is the single authority for "which rows belong to this tenant", so a
missing filter fails **closed** (you see nothing). Application code may add its
own scoping for ergonomics, but RLS is the backstop.

### Three database roles (privilege boundaries enforced by Postgres)

| role           | used for                                           | RLS                       |
|----------------|----------------------------------------------------|---------------------------|
| `app_owner`    | migrations / DDL only, never at request time       | subject (FORCE)           |
| `app_runtime`  | partner-facing request path                        | subject, **NOBYPASSRLS**  |
| `app_platform` | direct-customer / platform-admin / Stripe webhooks | **BYPASSRLS**             |

Partner requests can only ever run as `app_runtime`, which cannot see across
tenants no matter what the query says.

### Safe migration / backward compatibility

- New partner-owned tables (`partners`, `companies`, `memberships`,
  `partner_activity_log`): RLS **ENABLED and FORCED** → fail closed, even for the
  owner, even with no tenant context set.
- The pre-existing `users` table gains `partner_id` / `billing_source` with safe
  defaults (nil-sentinel partner + `stripe`) and RLS **ENABLED but not FORCED**,
  so the existing direct-customer + Stripe path (`app_platform`) is unchanged.

### Tenant scope comes from the server, never the client

`partner_id` is derived from the authenticated principal and applied with
`SET LOCAL` (transaction-scoped, pooling-safe). The client never supplies it.

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

## Run it

    make up      # postgres + auto-migrate + api on :8000
    make test    # tenant-isolation suite

Or: `docker compose up -d --build`, then `docker compose exec api pytest`.

## What the tests prove (`tests/test_tenant_isolation.py`)

- a partner sees only its own companies / activity log / partner row
- reading another partner's row by id returns nothing
- a cross-tenant UPDATE affects 0 rows
- inserting a row for another partner is rejected (WITH CHECK)
- with no tenant context, partner tables return nothing (fail closed)
- a partner cannot see direct-customer users
- the platform path still sees across all tenants (existing flow intact)

## Roadmap

- **Phase 1 (done):** schema, RLS isolation core, isolation tests.
- **Phase 2 (done):** revocable sessions + server-resolved principal, partner
  activation/suspension (+ cascade token revocation), domain deactivation,
  workspace parent/child tree, scope-inheritance rule, Stripe-bypass decision.
- **Phase 3:** server-side RBAC guards (Super Admin / Company Admin / Author /
  Read-Only) on every mutation, two-step transactional CSV onboarding,
  invitation emails.
- **Phase 4:** activity-log API (pagination + date/event filters), branding
  inheritance, billing-contact controls.
- **Phase 5:** workflow-template cloning, connector checks, token-usage tracking,
  60-day suspension retention + 1-year archiving, docs, PR, walkthrough.

## Known limitations (Phase 2)

- RBAC beyond the Super Admin scope-inheritance rule is not yet enforced on
  *every* mutation; the per-endpoint Company Admin / Author / Read-Only guards
  land in Phase 3.
- `resolve_branding` demonstrates parent-hub inheritance, but the full branding
  and billing-contact API is Phase 4.
- Data migrations that backfill FORCED tables must set `app.partner_id` (or
  temporarily relax FORCE); noted for later data migrations.
