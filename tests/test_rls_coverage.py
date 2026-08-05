"""What each database role can reach, and what confines it.

WHY THIS FILE EXISTS

test_toctou_lifecycle.py asserts that every partner-scoped table carries the
active-state gate, enumerating like this:

    SELECT tablename FROM pg_policies
    WHERE policyname = 'partner_isolation' AND ... NOT LIKE '%partner_is_active%'

Read the FROM clause. That query can answer "among the tables that already have
a partner_isolation policy, did any forget the gate?" A table with no policy at
all is not in the result set, is not in the negation of it, and cannot be. The
guard drew its inventory from the same catalog the thing it guards writes to.

0013 created outbox_events and never enabled row security. That test passed.

WHAT MAKES IT FAIL CLOSED

Before 0020, db/init/00-roles.sql contained an ALTER DEFAULT PRIVILEGES grant
that made every new table automatically accessible to app_runtime and app_platform.
Under those rules, forgetting to write a policy meant the table was fail-open
(world-writable across tenants).

After 0020, that blanket grant is gone (and verify_fixes.py R16 now guards
db/init against its return). A table without a policy is simply unreachable
(fail-closed) because it lacks the necessary GRANT. Therefore, this coverage
script no longer catches "someone forgot to do anything". Instead, it catches
the specific, narrower failure where "someone explicitly granted access to a
confined role, but forgot the policy".

THE TWO ENUMERATION RULES

1. Tables come from privileges, not from policies and not from column names. A
   table cannot leave the set by being forgotten; it leaves only by having its
   grants revoked, which is an explicit act someone performs on purpose.

2. ROLES come from pg_roles, not from a list in this file. A hardcoded role list
   is the same disease one level up: it works until someone adds a role and
   forgets to add it here, and the day that happens is exactly the day the new
   privilege surface exists. app_dispatcher does not exist yet. When it does,
   this file inspects it the same day it is created, with no edit.

AND ONE RULE ABOUT THE GUARD ITSELF

A role with BYPASSRLS does not FAIL the policy assertions below -- it makes them
vacuous. Row security is simply not applied to it, so "every table it reaches
has a gated policy" can be true while meaning nothing. That is the shape of
failure where an auditor is disarmed rather than defeated, so the set of
bypassing roles is pinned in both directions and checked before anything else.
"""
import pytest
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Registries. Each is asserted in BOTH directions, so an entry that stops being
# true fails instead of quietly widening what is accepted.
# ---------------------------------------------------------------------------

# Roles outside row security entirely. For these the ONLY control is the grant.
BYPASS_ROLES = {
    "app_platform": "pre-existing direct-customer and platform-admin path (0002)",
}

# Owns every table, so its access is inherent rather than granted and the
# privilege functions report true for everything. Excluded from the reach scan
# and pinned separately by test_app_owner_owns_every_table.
OWNER_ROLE = "app_owner"

# ENABLE without FORCE. FORCE binds the table OWNER; app_platform is BYPASSRLS
# either way, so the difference is only whether migrations read across tenants.
# Deliberate, documented in 0002/0003.
NOT_FORCED = {"users", "sessions"}

# Tenancy keyed on `id`, and the policy is deliberately NOT gated on
# partner_is_active(): the function reads `partners`, so a policy on `partners`
# calling it re-enters itself (0011 died this way once). The lifecycle write is
# taken away by grant instead.
UNGATED_POLICY = {"partners"}

# EMPTY since 0015. 0011 left billing_contact_email writable from the runtime
# path -- legitimate self-service -- but the partners policy is ungated, so that
# column sat outside the active-state gate and a stale request could write it
# after a suspension committed. 0015 revoked it and moved the write into
# set_active_partner_billing_contact(), which applies the gate itself.
PARTNERS_RUNTIME_COLUMNS: set[tuple[str, str]] = set()

# Migration bookkeeping. No application role has business here whatever its
# row-security status: `alembic check` is one of this project's three release
# gates, and a gate whose ground truth is writable by the thing it constrains is
# not a gate.
LEDGER_TABLES = {"alembic_version"}

# (role, table) -> why. A PERMISSIVE policy whose qual is `true` IS that role's
# BYPASSRLS for that table, spelled longer and opted into per table. The longer
# spelling is a real improvement -- per-table rather than global -- but it must
# be named for what it is, or a coverage test that only asks "is there a gated
# policy" stays green while a table becomes globally readable.
#
# app_dispatcher (0018). Three tables, each argued for separately -- the point
# of registering them one at a time is that a fourth would show up here as a
# failure rather than as nothing.
PERMISSIVE_TRUE: dict[tuple[str, str], str] = {
    ("app_dispatcher", "outbox_events"):
        "claims work across tenants; that IS the job",
    ("app_dispatcher", "invitations"):
        "reads status and expires_at to decide deliverability; column-scoped "
        "so token_hash stays unreadable",
    ("app_dispatcher", "partners"):
        "partner_is_active() is SECURITY INVOKER and reads this table as the "
        "caller -- without the policy it returns false for every partner and "
        "the dispatcher silently delivers nothing",
}


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

# starts_with() rather than LIKE 'app\\_%': no escape to get wrong, in the SQL
# or in the Python string literal wrapping it.
ROLE_SQL = """
SELECT rolname, rolsuper, rolbypassrls
FROM pg_roles
WHERE rolcanlogin AND starts_with(rolname, 'app_')
ORDER BY rolname
"""

REACH_SQL = """
SELECT
    r.rolname                                            AS role_name,
    c.relname                                            AS table_name,
    c.relowner::regrole::text                            AS table_owner,
    -- has_any_column_privilege, not has_table_privilege: grants in this schema
    -- are column-level in places (0011, 0015) and the table-level function
    -- returns false for those. A table-level-only scan would report the most
    -- surgically granted tables as unreachable and skip every assertion on them.
    has_any_column_privilege(r.rolname, c.oid, 'SELECT') AS can_select,
    has_any_column_privilege(r.rolname, c.oid, 'INSERT') AS can_insert,
    has_any_column_privilege(r.rolname, c.oid, 'UPDATE') AS can_update,
    -- DELETE has no column-level form; has_any_column_privilege raises on it.
    has_table_privilege     (r.rolname, c.oid, 'DELETE') AS can_delete,
    c.relrowsecurity                                     AS rls_enabled,
    c.relforcerowsecurity                                AS rls_forced,
    EXISTS (
        SELECT 1 FROM pg_attribute a
        WHERE a.attrelid = c.oid AND a.attname = 'partner_id'
          AND a.attnum > 0 AND NOT a.attisdropped
    )                                                    AS has_partner_id
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (
    SELECT rolname FROM pg_roles
    WHERE rolcanlogin AND starts_with(rolname, 'app_')
) r
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
ORDER BY r.rolname, c.relname
"""

POLICY_SQL = """
SELECT tablename,
       policyname,
       permissive,
       roles::text[]            AS roles,
       coalesce(qual, '')       AS qual,
       coalesce(with_check, '') AS with_check
FROM pg_policies
WHERE schemaname = 'public'
"""

# Column-level grants, read from pg_attribute.attacl.
#
# NOT information_schema.column_privileges: that view only shows grants
# involving a "currently enabled role", i.e. one the connected user is a member
# of. The test connects as app_platform and is not a member of app_runtime, so
# the view would return zero rows and every assertion built on it would pass for
# the wrong reason.
COLUMN_GRANT_SQL = """
SELECT r.rolname  AS role_name,
       c.relname  AS table_name,
       a.attname  AS column_name,
       acl.privilege_type
FROM pg_attribute a
JOIN pg_class     c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
JOIN pg_roles     r ON r.oid = acl.grantee
WHERE n.nspname = 'public'
  AND r.rolcanlogin AND starts_with(r.rolname, 'app_')
  AND a.attnum > 0 AND NOT a.attisdropped
"""


class Scan:
    def __init__(self, roles, reach, policies, column_grants):
        self.roles = roles
        self.reach = reach
        self.policies = policies
        self.column_grants = column_grants

    def confined_roles(self):
        """Application roles that row security actually applies to."""
        return [r.rolname for r in self.roles
                if not r.rolbypassrls and r.rolname != OWNER_ROLE]

    def bypass_roles(self):
        return [r.rolname for r in self.roles if r.rolbypassrls]

    def rows_for(self, role_name):
        return [t for t in self.reach if t.role_name == role_name]

    def reachable(self, role_name):
        return [t for t in self.rows_for(role_name)
                if t.can_select or t.can_insert or t.can_update or t.can_delete]

    def writable(self, role_name):
        return [t for t in self.rows_for(role_name)
                if t.can_insert or t.can_update or t.can_delete]

    def policies_on(self, table_name):
        return [p for p in self.policies if p.tablename == table_name]

    @staticmethod
    def applies_to(policy, role_name):
        """PostgreSQL renders TO PUBLIC as the role name 'public'."""
        return "public" in policy.roles or role_name in policy.roles


@pytest.fixture(scope="module")
def scan(platform_engine):
    """One catalog read; every question below is asked of it.

    Runs on the platform connection because it needs to see the whole schema.
    Nothing here depends on RLS -- the privilege functions answer about any role
    regardless of who is asking.
    """
    with platform_engine.connect() as c:
        return Scan(
            roles=c.execute(text(ROLE_SQL)).all(),
            reach=c.execute(text(REACH_SQL)).all(),
            policies=c.execute(text(POLICY_SQL)).all(),
            column_grants=c.execute(text(COLUMN_GRANT_SQL)).all(),
        )


# ---------------------------------------------------------------------------
# 0. the guard has to be able to fail
# ---------------------------------------------------------------------------

def test_the_scan_sees_the_roles_and_the_schema(scan):
    """Every list-and-assert-empty test in this file is vacuously green if the
    scan comes back empty.

    Not hypothetical: an earlier assertion in this project used repeat('x', 64)
    as a token, matched no rows, and "passed" while testing nothing. So the scan
    is anchored first, against roles and tables that have existed since
    0002/0006 and are not what any of this is trying to detect.
    """
    names = {r.rolname for r in scan.roles}
    missing_roles = {"app_owner", "app_runtime", "app_platform"} - names
    assert not missing_roles, (
        f"the role scan did not find {sorted(missing_roles)}, which db/init "
        f"creates. The scan is broken and every other assertion here is passing "
        f"vacuously. Found: {sorted(names)}")

    reachable = {t.table_name for t in scan.reachable("app_runtime")}
    anchors = {"companies", "memberships", "partner_activity_log", "workflows"}
    missing_tables = anchors - reachable
    assert not missing_tables, (
        f"the privilege scan did not find {sorted(missing_tables)}, which "
        f"app_runtime has held DML on since 0002/0006. Found: {sorted(reachable)}")

    assert scan.policies, "pg_policies returned nothing; the policy scan is broken"


# ---------------------------------------------------------------------------
# 1. the guard must not be disarmable
# ---------------------------------------------------------------------------

def test_no_application_role_is_a_superuser(scan):
    """A superuser is exempt from row security AND from grants, so it makes
    every other assertion in this file meaningless at once. Checked separately
    from BYPASSRLS because it is a strictly larger hole and the fix differs.
    """
    supers = sorted(r.rolname for r in scan.roles if r.rolsuper)
    assert supers == [], (
        f"{supers} are superusers. Nothing below constrains them: row security "
        f"does not apply, grants do not apply, and every test in this file "
        f"would still pass.")


def test_only_the_declared_roles_bypass_rls(scan):
    """The disarm check, pinned in both directions.

    A role that gains BYPASSRLS does not fail the policy assertions below -- it
    silently exempts itself from them. The failure this rules out is not "a role
    got too much access" but "the tests kept passing about a role they no longer
    describe".

    This has to be right before app_dispatcher exists. Created with BYPASSRLS by
    accident, it would sail through every RLS check in this file while being
    confined by nothing.
    """
    actual = set(scan.bypass_roles())
    declared = set(BYPASS_ROLES)

    problems = []
    if undeclared := actual - declared:
        problems.append(
            f"{sorted(undeclared)} bypass row security and are not declared "
            f"here. Every RLS assertion in this file is vacuous for them.")
    if stale := declared - actual:
        problems.append(
            f"BYPASS_ROLES lists {sorted(stale)}, which no longer bypass row "
            f"security (or no longer exist). Remove them so the RLS assertions "
            f"start applying -- a stale entry here is an exemption nobody "
            f"decided on.")
    assert problems == [], "\n  ".join([""] + problems)


def test_app_owner_owns_every_table(scan):
    """app_owner is excluded from the reach scan because ownership is not a
    grant -- the privilege functions report true for everything it owns, so
    including it would produce a list of violations that cannot be revoked.

    That exclusion is only safe while it really is the owner of everything. A
    table owned by someone else would be silently outside both the exclusion's
    justification and every grant assertion below.
    """
    wrong = sorted({(t.table_name, t.table_owner) for t in scan.reach
                    if t.table_owner != OWNER_ROLE})
    assert wrong == [], (
        f"tables not owned by {OWNER_ROLE}: {wrong}. FORCE ROW LEVEL SECURITY "
        f"binds the owner, and every migration in this project assumes that "
        f"owner is {OWNER_ROLE}.")


# ---------------------------------------------------------------------------
# 2. confined roles: reachable => row security actually confines it
# ---------------------------------------------------------------------------

def test_every_table_a_confined_role_reaches_has_rls_enabled(scan):
    """The headline check, and the one a pg_policies-based guard cannot make.

    Reachable with row security off means the tenant boundary on that table is
    whatever the application remembered to write -- the adjudicator this schema
    exists to argue against.
    """
    problems = []
    for role in scan.confined_roles():
        unprotected = sorted(t.table_name for t in scan.reachable(role)
                             if not t.rls_enabled)
        if unprotected:
            problems.append(f"{role}: {unprotected}")
    assert problems == [], (
        "roles that row security applies to, reaching tables with none:\n  "
        + "\n  ".join(problems)
        + "\nSince 0020 a table is born ungranted, so this is not a forgotten "
          "table -- someone granted a confined role access to it and did not "
          "write the policy that scopes what it can reach.")


def test_every_table_a_confined_role_reaches_forces_rls(scan):
    """FORCE is what makes the boundary hold for the table owner too.

    Reported separately from the ENABLE check on purpose: ENABLE-without-FORCE
    is a real and different state (users, sessions), and collapsing the two
    would hide it.
    """
    problems = []
    for role in scan.confined_roles():
        unforced = sorted(t.table_name for t in scan.reachable(role)
                          if t.rls_enabled and not t.rls_forced
                          and t.table_name not in NOT_FORCED)
        if unforced:
            problems.append(f"{role}: {unforced}")
    assert problems == [], (
        "enabled but not forced, and not in NOT_FORCED:\n  " + "\n  ".join(problems)
        + "\nMigrations run as the table owner: without FORCE the owner reads "
          "and writes across every tenant.")


def test_every_reachable_tenant_table_has_a_policy_for_that_role(scan):
    """ENABLE alone is fail-closed but useless; the policy makes the table
    usable AND scoped, and the gate makes suspension mean something.

    Note the shape of the per-role check: a policy counts for a role only if it
    APPLIES to that role. A gated partner_isolation policy TO PUBLIC covers
    every role; one scoped TO some other role does not, and a future role added
    without its own policy would otherwise appear covered by someone else's.
    """
    registered = {(tbl, role) for (role, tbl) in PERMISSIVE_TRUE}
    problems = []
    for role in scan.confined_roles():
        for t in scan.reachable(role):
            if not t.has_partner_id or t.table_name in UNGATED_POLICY:
                continue
            applicable = [p for p in scan.policies_on(t.table_name)
                          if scan.applies_to(p, role)]
            if not applicable:
                problems.append(f"{role} / {t.table_name}: no policy applies")
                continue
            gated = [p for p in applicable
                     if "partner_id" in p.qual and "partner_id" in p.with_check
                     and "partner_is_active" in p.qual
                     and "partner_is_active" in p.with_check]
            if not gated and (t.table_name, role) not in registered:
                names = sorted(p.policyname for p in applicable)
                problems.append(
                    f"{role} / {t.table_name}: policies {names} apply but none "
                    f"scopes on partner_id AND gates on partner_is_active in "
                    f"both USING and WITH CHECK, and this pair is not a "
                    f"registered per-table bypass")
    assert problems == [], (
        "tenant tables reachable without a scoped, gated policy:\n  "
        + "\n  ".join(problems))


def test_a_confined_role_cannot_write_an_unscoped_table(scan):
    """A table with no partner_id cannot be tenant-scoped by any policy, so the
    only safe grant on it from a confined role is none.

    This is the assertion a column-driven inventory ("every table WITH a
    partner_id") cannot make, because such a table is not in its set. The
    scoping question and the reachability question have different answers, and
    only one of them is about columns.

    Bypassing roles are deliberately out of scope here: app_platform writing an
    unscoped table is the design (subscriptions is platform-only because 0020
    omitted its grant to app_runtime), and what confines it is the grant,
    checked separately.
    """
    problems = []
    for role in scan.confined_roles():
        offenders = sorted(t.table_name for t in scan.writable(role)
                           if not t.has_partner_id
                           and t.table_name not in UNGATED_POLICY)
        if offenders:
            problems.append(f"{role}: {offenders}")
    assert problems == [], (
        "confined roles holding INSERT/UPDATE/DELETE on tables with no "
        "partner_id:\n  " + "\n  ".join(problems)
        + "\nEither the table belongs to the platform path only (REVOKE ALL, as "
          "0020 does for subscriptions) or it needs a tenant column.")


# ---------------------------------------------------------------------------
# 3. per-table bypass, named for what it is
# ---------------------------------------------------------------------------

def test_permissive_true_policies_are_registered_and_never_public(scan):
    """`USING (true)` is BYPASSRLS for one table.

    app_dispatcher will need exactly this on three tables: it has to see other
    tenants' rows to dispatch them, and the alternative -- the role attribute --
    is that permission everywhere at once. Per-table opt-in is genuinely better.
    It is still a hole, and a coverage test that only asks "is there a gated
    policy" stays green through it, because adding a permissive policy does not
    remove the tenant one; permissive policies are OR'd.

    Two things are pinned. Each (role, table) must be registered with a reason,
    and no such policy may reach PUBLIC -- `TO PUBLIC USING (true)` would hand
    the bypass to every role including app_runtime.

    LIMIT: this recognises the literal `true`, which is the form anyone writes.
    A disguised tautology -- `USING (1=1)`, `USING (partner_id IS NOT NULL)` --
    reads as an ordinary predicate here. Closing that needs a registry of EVERY
    policy rather than of the suspicious ones, which is a bigger change than
    this step.
    """
    problems = []
    seen = set()
    for p in scan.policies:
        if not p.permissive:
            continue
        if p.qual.strip() != "true" and p.with_check.strip() != "true":
            continue
        if "public" in p.roles:
            problems.append(
                f"{p.tablename}.{p.policyname} is permissive-true and applies "
                f"to PUBLIC, which hands the bypass to every role including "
                f"app_runtime")
            continue
        for role in p.roles:
            seen.add((role, p.tablename))
            if (role, p.tablename) not in PERMISSIVE_TRUE:
                problems.append(
                    f"{p.tablename}.{p.policyname} gives {role} an unrestricted "
                    f"view of this table and is not in PERMISSIVE_TRUE. Register "
                    f"it with the reason it is needed, or narrow the policy.")

    if stale := set(PERMISSIVE_TRUE) - seen:
        problems.append(
            f"PERMISSIVE_TRUE lists {sorted(stale)}, which no longer exist. A "
            f"stale entry is permission to add one back without review.")

    assert problems == [], "\n  ".join([""] + problems)


# ---------------------------------------------------------------------------
# 4. the release gate's own ground truth
# ---------------------------------------------------------------------------

def test_no_application_role_may_write_the_migration_ledger(scan):
    """`alembic check` is one of this project's three release gates and it reads
    alembic_version. A gate whose ground truth is writable by the thing it
    constrains is not a gate.

    Applies to bypassing roles too -- especially, since row security would not
    have stopped them anyway. 0014 revoked this from app_runtime and went no
    further, which is the half-fix shape: the forbidden side written for one
    role and not for the others it is equally forbidden to.
    """
    problems = []
    for r in scan.roles:
        if r.rolname == OWNER_ROLE:
            continue  # owns the table; alembic writes it as the owner
        offenders = sorted(t.table_name for t in scan.writable(r.rolname)
                           if t.table_name in LEDGER_TABLES)
        if offenders:
            problems.append(f"{r.rolname}: {offenders}")
    assert problems == [], (
        "application roles that can rewrite migration bookkeeping:\n  "
        + "\n  ".join(problems)
        + "\nREVOKE ALL ON alembic_version FROM <role>.")


# ---------------------------------------------------------------------------
# 5. the exemptions, asserted in both directions
# ---------------------------------------------------------------------------

def test_the_exemptions_are_still_true(scan):
    """An allowlist is a place to forget, so it is pinned from both sides.

    Listed-but-no-longer-true is the dangerous direction: it means this file is
    accepting a state nobody decided on. Newly-true-but-unlisted is the other,
    and it means a table quietly left the protected set.
    """
    by_name = {t.table_name: t for t in scan.rows_for("app_runtime")}
    problems = []

    actually_unforced = {t.table_name for t in scan.rows_for("app_runtime")
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

    partners = by_name.get("partners")
    if partners is None:
        problems.append("`partners` is missing from the scan")
    else:
        if partners.can_insert or partners.can_update or partners.can_delete:
            problems.append(
                "app_runtime holds INSERT, UPDATE or DELETE on `partners`. "
                "Since 0015 the runtime path holds no write on this table at "
                "all -- billing goes through the controlled function, which "
                "applies the active-state gate the ungated policy cannot.")
        held = {(g.column_name, g.privilege_type) for g in scan.column_grants
                if g.table_name == "partners" and g.role_name == "app_runtime"}
        if held != PARTNERS_RUNTIME_COLUMNS:
            problems.append(
                f"column grants on `partners` for app_runtime are "
                f"{sorted(held)}, expected {sorted(PARTNERS_RUNTIME_COLUMNS)}. "
                f"The policy here checks only `id` and does NOT gate on "
                f"partner_is_active, so any column reachable from the runtime "
                f"path lets a suspended tenant act on its own lifecycle row.")

    assert problems == [], "\n  ".join([""] + problems)
