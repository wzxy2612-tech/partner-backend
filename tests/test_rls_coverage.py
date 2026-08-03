"""RLS coverage, enumerated from PRIVILEGES rather than from policies.

WHY THIS FILE EXISTS

test_toctou_lifecycle.py already asserts that every partner-scoped table carries
the active-state gate. It does it like this:

    SELECT tablename FROM pg_policies
    WHERE policyname = 'partner_isolation' AND ... NOT LIKE '%partner_is_active%'

Read the FROM clause. The question that query can answer is "among the tables
that already have a partner_isolation policy, did any forget the gate?" A table
with no policy at all is not in the result set, is not in the negation of the
result set, and cannot be. The guard draws its inventory from the same catalog
the thing it guards writes to, so the one failure it is structurally unable to
see is the total absence of a policy.

0013 created outbox_events and never enabled row security on it. The existing
coverage test passed. So did the 0011 preflight, which compares pg_policies to a
hand-written list and therefore shares the blind spot.

WHAT MAKES IT FAIL OPEN

db/init/00-roles.sql:35 -

    ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime, app_platform;

Creating a table and protecting a table are two separate acts, and only the
first one is required to happen. Every table app_owner creates is immediately
and automatically writable by the partner-facing role; row security is opt-in on
top. "Forgot the policy" therefore means "world-writable across tenants", not
"unusable" -- the inverse of the fail-closed property the rest of the schema is
built on.

THE ENUMERATION RULE

This file starts from "what can app_runtime reach" and asks what protects it.
That set comes from pg_class + the privilege functions, which no migration in
this repo writes to and no application code consults. A table cannot leave the
set by being forgotten; it leaves only by having its grants revoked, which is an
explicit act someone has to perform on purpose.

Grant-driven, not column-driven. "Every table with a partner_id column" is the
other tempting inventory and it is weaker: it silently approves any reachable
table that has no tenant column at all, which is its own category of hole (see
test_the_runtime_role_cannot_write_an_unscoped_table).
"""
import pytest
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Exemptions. Both are asserted in BOTH directions by
# test_the_exemptions_are_still_true, so an entry that stops being true fails
# instead of quietly widening what the rest of the file will accept.
# ---------------------------------------------------------------------------

# ENABLE without FORCE. Pre-existing tables from the direct-customer schema
# (0002/0003). FORCE binds the table OWNER; app_platform is BYPASSRLS either
# way, so the difference here is only whether app_owner -- migrations -- can
# read across tenants. Deliberate, documented in 0002.
NOT_FORCED = {"users", "sessions"}

# Tenancy keyed on `id`, not `partner_id`, and the policy is deliberately NOT
# gated on partner_is_active(): the function reads `partners`, so a policy on
# `partners` calling it re-enters itself (0011 died this way once, taking 36
# tests with it). The lifecycle write is taken away by grant instead -- which is
# what test_the_exemptions_are_still_true pins.
UNGATED_POLICY = {"partners"}

# EMPTY, since 0015. 0011 left one column writable from the runtime path --
# billing_contact_email, legitimate tenant self-service -- but the partners
# policy is ungated, so that column sat outside the active-state gate and a
# stale request could write it after a suspension committed. 0015 revoked it and
# moved the write into a SECURITY DEFINER function that applies the gate itself.
#
# Anything appearing here again means some column of `partners` became writable
# from the runtime path, which under an ungated policy means a suspended tenant
# can act on its own lifecycle row.
PARTNERS_RUNTIME_COLUMNS: set[tuple[str, str]] = set()


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

SCAN_SQL = """
SELECT
    c.relname                                                AS table_name,
    -- has_any_column_privilege, not has_table_privilege: after 0011 the runtime
    -- role holds UPDATE on partners only at COLUMN level, and the table-level
    -- function returns false for it. A table-level-only scan would report
    -- `partners` as unreachable and skip every assertion below on the one table
    -- whose grants are the most surgical in the schema.
    has_any_column_privilege('app_runtime', c.oid, 'SELECT') AS can_select,
    has_any_column_privilege('app_runtime', c.oid, 'INSERT') AS can_insert,
    has_any_column_privilege('app_runtime', c.oid, 'UPDATE') AS can_update,
    -- DELETE has no column-level form in PostgreSQL; has_any_column_privilege
    -- raises on it. This asymmetry is why the four are not one loop.
    has_table_privilege     ('app_runtime', c.oid, 'DELETE') AS can_delete,
    c.relrowsecurity                                         AS rls_enabled,
    c.relforcerowsecurity                                    AS rls_forced,
    EXISTS (
        SELECT 1 FROM pg_attribute a
        WHERE a.attrelid = c.oid AND a.attname = 'partner_id'
          AND a.attnum > 0 AND NOT a.attisdropped
    )                                                        AS has_partner_id
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p')
ORDER BY c.relname
"""

POLICY_SQL = """
SELECT tablename,
       policyname,
       coalesce(qual, '')       AS qual,
       coalesce(with_check, '') AS with_check
FROM pg_policies
WHERE schemaname = 'public'
"""

# Column-level grants held by app_runtime, read from pg_attribute.attacl.
#
# NOT information_schema.column_privileges: that view only shows grants
# involving a "currently enabled role", i.e. one the connected user is a member
# of. The test connects as app_platform, which is not a member of app_runtime,
# so the view would return zero rows and every assertion built on it would pass
# for the wrong reason.
COLUMN_GRANT_SQL = """
SELECT c.relname AS table_name,
       a.attname AS column_name,
       acl.privilege_type
FROM pg_attribute a
JOIN pg_class     c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
JOIN pg_roles     r ON r.oid = acl.grantee
WHERE n.nspname = 'public'
  AND r.rolname = 'app_runtime'
  AND a.attnum > 0 AND NOT a.attisdropped
"""


class Scan:
    def __init__(self, tables, policies, column_grants):
        self.tables = tables
        self.policies = policies
        self.column_grants = column_grants

    def reachable(self):
        """Anything app_runtime can read or write at all."""
        return [t for t in self.tables
                if t.can_select or t.can_insert or t.can_update or t.can_delete]

    def writable(self):
        return [t for t in self.tables
                if t.can_insert or t.can_update or t.can_delete]

    def policies_on(self, table_name):
        return [p for p in self.policies if p.tablename == table_name]


@pytest.fixture(scope="module")
def scan(platform_engine):
    """One catalog read, six questions asked of it.

    Runs on the platform connection because it needs to see the whole schema;
    nothing here depends on RLS, and the privilege functions answer about
    app_runtime regardless of who is asking.
    """
    with platform_engine.connect() as c:
        return Scan(
            tables=c.execute(text(SCAN_SQL)).all(),
            policies=c.execute(text(POLICY_SQL)).all(),
            column_grants=c.execute(text(COLUMN_GRANT_SQL)).all(),
        )


# ---------------------------------------------------------------------------
# 0. the guard has to be able to fail
# ---------------------------------------------------------------------------

def test_the_scan_actually_sees_the_schema(scan):
    """A coverage check whose inventory query returns nothing passes everything.

    That is not hypothetical here: an earlier assertion in this project used
    repeat('x', 64) as a token and matched no rows, so it "passed" while testing
    nothing at all. Every list-and-assert-empty test in this file is vacuously
    green if the scan comes back empty, so the scan is anchored first, against
    tables that have existed since 0002/0006 and are not what any of this is
    trying to detect.
    """
    reachable = {t.table_name for t in scan.reachable()}
    anchors = {"companies", "memberships", "partner_activity_log", "workflows"}
    missing = anchors - reachable
    assert not missing, (
        f"the privilege scan did not find {sorted(missing)}, which app_runtime "
        f"has held DML on since 0002/0006. The scan is broken, and every other "
        f"assertion in this file is passing vacuously. Found: {sorted(reachable)}")
    assert scan.policies, "pg_policies returned nothing; the policy scan is broken"


# ---------------------------------------------------------------------------
# 1. reachable => row security is on
# ---------------------------------------------------------------------------

def test_every_table_the_runtime_role_can_reach_has_rls_enabled(scan):
    """The headline check, and the one the pg_policies-based guard cannot make.

    Reachable with row security off means the tenant boundary on that table is
    whatever the application remembered to write -- the adjudicator this schema
    exists to argue against.
    """
    unprotected = sorted(t.table_name for t in scan.reachable() if not t.rls_enabled)
    assert unprotected == [], (
        f"app_runtime can reach {unprotected} with no row security. Default "
        f"privileges (db/init/00-roles.sql) grant DML on every new table "
        f"automatically, so a table without ENABLE ROW LEVEL SECURITY is not "
        f"unreachable -- it is cross-tenant readable and writable.")


def test_every_table_the_runtime_role_can_reach_forces_rls(scan):
    """FORCE is what makes the boundary hold for the table owner too.

    Reported separately from the ENABLE check on purpose: a table can be
    ENABLEd and not FORCEd, which is a real and different state (users,
    sessions), and collapsing the two would hide it.
    """
    unforced = sorted(t.table_name for t in scan.reachable()
                      if t.rls_enabled and not t.rls_forced
                      and t.table_name not in NOT_FORCED)
    assert unforced == [], (
        f"{unforced} have row security enabled but not forced, and are not in "
        f"NOT_FORCED. Migrations run as app_owner, which is the table owner: "
        f"without FORCE the owner reads and writes across every tenant.")


# ---------------------------------------------------------------------------
# 2. reachable + tenant column => a gated policy
# ---------------------------------------------------------------------------

def test_every_reachable_tenant_table_has_a_gated_isolation_policy(scan):
    """ENABLE alone is fail-closed but useless; the policy is what makes the
    table usable AND scoped, and the gate is what makes suspension mean
    something. Both halves are checked here because a table can have one
    without the other and the failure modes are opposite.
    """
    problems = []
    for t in scan.reachable():
        if not t.has_partner_id or t.table_name in UNGATED_POLICY:
            continue
        pols = scan.policies_on(t.table_name)
        if not pols:
            problems.append(f"{t.table_name}: no policy at all")
            continue
        scoped_and_gated = [
            p for p in pols
            if "partner_id" in p.qual and "partner_id" in p.with_check
            and "partner_is_active" in p.qual
            and "partner_is_active" in p.with_check
        ]
        if not scoped_and_gated:
            names = sorted(p.policyname for p in pols)
            problems.append(
                f"{t.table_name}: policies {names} exist but none scopes on "
                f"partner_id AND gates on partner_is_active in both USING and "
                f"WITH CHECK")
    assert problems == [], (
        "tenant tables reachable by app_runtime without a scoped, gated "
        "policy:\n  " + "\n  ".join(problems))


# ---------------------------------------------------------------------------
# 3. reachable + NO tenant column => must not be writable
# ---------------------------------------------------------------------------

def test_the_runtime_role_cannot_write_an_unscoped_table(scan):
    """A table with no partner_id cannot be tenant-scoped by any policy, so the
    only safe grant on it from the partner-facing role is none.

    This is the assertion a column-driven inventory ("every table WITH a
    partner_id") cannot make, because such a table is not in its set. The
    scoping question and the reachability question have different answers, and
    only one of them is about columns.
    """
    offenders = sorted(
        t.table_name for t in scan.writable()
        if not t.has_partner_id and t.table_name not in UNGATED_POLICY)
    assert offenders == [], (
        f"app_runtime holds INSERT/UPDATE/DELETE on {offenders}, which carry no "
        f"partner_id and therefore cannot be tenant-scoped by any policy. "
        f"Either the table belongs to the platform path only (REVOKE ALL, as "
        f"0008 does for subscriptions) or it needs a tenant column.")


# ---------------------------------------------------------------------------
# 4. the exemptions, asserted in both directions
# ---------------------------------------------------------------------------

def test_the_exemptions_are_still_true(scan):
    """An allowlist is a place to forget, so it is pinned from both sides.

    Listed-but-no-longer-true is the dangerous direction: it means this file is
    accepting a state nobody decided on. Newly-true-but-unlisted is the other,
    and it means a table quietly left the protected set.
    """
    by_name = {t.table_name: t for t in scan.tables}
    problems = []

    # NOT_FORCED must name exactly the enabled-but-unforced tables.
    actually_unforced = {t.table_name for t in scan.tables
                         if t.rls_enabled and not t.rls_forced}
    if stale := NOT_FORCED - actually_unforced:
        problems.append(
            f"NOT_FORCED lists {sorted(stale)}, which now FORCE row security "
            f"(or no longer exist). Remove them -- a stale exemption is an "
            f"assertion this file has stopped making.")
    if extra := actually_unforced - NOT_FORCED:
        problems.append(
            f"{sorted(extra)} became ENABLE-without-FORCE and nobody decided "
            f"that here.")

    # partners: ungated policy is only safe because the write was taken away.
    # If that grant ever widens, the exemption above stops being justified.
    partners = by_name.get("partners")
    if partners is None:
        problems.append("`partners` is missing from the scan")
    else:
        if partners.can_insert or partners.can_delete:
            problems.append(
                "app_runtime holds INSERT or DELETE on `partners`. Creating or "
                "destroying tenants is never a runtime action, and the policy "
                "on this table is ungated.")
        held = {(g.column_name, g.privilege_type) for g in scan.column_grants
                if g.table_name == "partners"}
        if held != PARTNERS_RUNTIME_COLUMNS:
            problems.append(
                f"column grants on `partners` for app_runtime are "
                f"{sorted(held)}, expected {sorted(PARTNERS_RUNTIME_COLUMNS)}. "
                f"The policy here checks only `id` and does NOT gate on "
                f"partner_is_active, so any lifecycle column reachable from "
                f"the runtime path lets a suspended tenant walk out of its own "
                f"suspension.")

    assert problems == [], "\n  ".join([""] + problems)
