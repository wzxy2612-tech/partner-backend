"""functions are born unreachable, like tables since 0020

PostgreSQL grants EXECUTE on a new function to PUBLIC. Not through
ALTER DEFAULT PRIVILEGES -- through a hardwired default that shows up as
`proacl IS NULL`. So this is root cause A in its second form: an object is
reachable before anyone decides it should be, and 0020 closed only the table
half.

0015 already had the right shape (REVOKE ALL FROM PUBLIC, then one explicit
GRANT). 0011 did not: it granted EXECUTE to app_runtime and left PUBLIC's
default in place, so the grant looked like the decision while the default was
the reality. The rule was written down four migrations after the violation and
never backfilled -- the same half-fix shape this schema keeps producing, with
the clock running the other way.

WHAT THIS DOES NOT CLOSE

partner_is_active() is SECURITY INVOKER, so a caller with EXECUTE but no SELECT
on `partners` gets 42501 rather than an answer. PUBLIC EXECUTE was therefore not
a status oracle for any role that exists today. What it was is a grant nobody
made, waiting for the next role: app_dispatcher was created in 0018 and would
have inherited it for free. Reach that arrives with the role rather than with a
decision is the thing being removed.

THE TRAP FOR WHOEVER TOUCHES THESE FUNCTIONS NEXT

CREATE OR REPLACE preserves a function's ACL. DROP + CREATE does not. With the
default privilege revoked below, a dropped-and-recreated partner_is_active comes
back with no grants at all -- and twelve policies call it, so every confined
role starts failing at query time, not at migration time. Replace, do not drop.
If you must drop, re-grant in the same migration.

Revision ID: 0021
Revises: 0020
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


# Who must be able to call what, and why. Every entry is a decision; an empty
# list is also a decision.
#
# protect_platform_tenant() is absent on purpose. It is a trigger function, and
# PostgreSQL checks EXECUTE when the trigger is CREATED, not when it fires -- so
# no role needs a grant for DML to keep working, and granting one would only
# make the function directly callable.
FUNCTION_GRANTS: list[tuple[str, list[str]]] = [
    # Twelve policies, accept_invitation, login, the billing DEFINER function
    # and the dispatcher's claim all read it.
    #   app_runtime    -- login and the invitation path evaluate it directly
    #   app_dispatcher -- its three 0018 policies and _claim evaluate it
    #   app_platform   -- BYPASSRLS skips policies, not function privileges, and
    #                     _claim runs under it in the test suite
    ("public.partner_is_active(uuid)",
     ["app_runtime", "app_platform", "app_dispatcher"]),

    # 0015's decision, restated so this file is the whole picture rather than a
    # patch on top of one. The runtime role writes the billing contact only
    # through this DEFINER function; nothing else calls it.
    ("public.set_active_partner_billing_contact(text)", ["app_runtime"]),
]


AUDIT_VIEW = """
CREATE OR REPLACE VIEW audit_public_function_execute AS
SELECT
    p.oid::regprocedure::text AS function_identity,
    CASE WHEN p.proacl IS NULL
         THEN 'default acl -- PUBLIC holds EXECUTE'
         ELSE 'PUBLIC holds an explicit EXECUTE grant'
    END AS reason
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  -- proacl IS NULL is the whole trap. It does not mean "no grants"; it means
  -- "the default", and the default for a function INCLUDES PUBLIC EXECUTE. A
  -- guard written as aclexplode(p.proacl) alone returns zero rows for exactly
  -- the functions nobody has ever thought about, and reports them clean.
  AND (p.proacl IS NULL
       OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0));
"""

VIEW_COMMENT = """
COMMENT ON VIEW audit_public_function_execute IS
'0021 single predicate. Postflight and tests/test_function_grants.py both read '
'it: non-empty is a violation. The table-side equivalent is '
'audit_default_privileges from 0020.';
"""


# State-driven, like 0020's revoke: sweep whatever is actually there rather than
# a list that can fall behind the schema. regprocedure renders a quoted,
# argument-typed identity, so it is safe to interpolate.
REVOKE_PUBLIC = """
DO $$
DECLARE
    rec record;
BEGIN
    FOR rec IN SELECT function_identity FROM audit_public_function_execute
    LOOP
        RAISE NOTICE 'function-acl: REVOKE ALL ON FUNCTION % FROM PUBLIC',
            rec.function_identity;
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',
                       rec.function_identity);
    END LOOP;
END
$$;
"""

# The gate, not the cleanup: a function created after this point is born with no
# PUBLIC EXECUTE, so reaching it takes a GRANT someone wrote. Tables got this in
# 0020 by DELETING the default privilege in db/init; functions need a default
# privilege ADDED, because the PUBLIC grant they carry is hardwired rather than
# configured. Opposite direction, same property.
#
# NO `IN SCHEMA` -- and the omission is the entire point. The schema-scoped form
# computes from an EMPTY acl, so revoking PUBLIC from nothing yields nothing,
# which equals "no entry", so PostgreSQL stores no row. The statement succeeds,
# reports nothing, and new functions keep the hardwired default. The unqualified
# form computes from acldefault(), so removing PUBLIC's EXECUTE leaves
# {app_owner=X/app_owner} -- different from the default, therefore stored, and
# therefore actually applied. Verified both ways in one transaction: scoped 0
# rows, unqualified 1 row and a probe function with a non-null proacl.
#
# The wider scope costs nothing: it is keyed to app_owner as grantor, and
# app_owner creates objects only in public. It also does not show up in 0020's
# audit_default_privileges, whose `grantee IS DISTINCT FROM defaclrole` filter
# already excludes an owner's self-grant.
DEFAULT_PRIVILEGE = """
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
"""

POSTFLIGHT = """
DO $$
DECLARE
    leftovers text;
BEGIN
    SELECT string_agg(format('%s (%s)', function_identity, reason), ', '
                      ORDER BY function_identity)
    INTO leftovers
    FROM audit_public_function_execute;

    IF leftovers IS NOT NULL THEN
        RAISE EXCEPTION 'postflight: PUBLIC still holds EXECUTE on: %', leftovers;
    END IF;
END
$$;
"""


def upgrade() -> None:
    op.execute(AUDIT_VIEW)
    op.execute(VIEW_COMMENT)
    op.execute(REVOKE_PUBLIC)
    op.execute(DEFAULT_PRIVILEGE)

    for identity, roles in FUNCTION_GRANTS:
        for role in roles:
            op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {role}")

    op.execute(POSTFLIGHT)


def downgrade() -> None:
    """Restores PUBLIC's EXECUTE, which is what 0021 removed.

    The explicit grants are NOT withdrawn. Under 0020 they were reachable
    through PUBLIC anyway, so withdrawing them would leave a 0020 world with
    less reach than it actually had -- the same asymmetry 0020's own downgrade
    documents. Provenance changes; effective privilege does not.
    """
    op.execute("""
        ALTER DEFAULT PRIVILEGES FOR ROLE app_owner
            GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
    """)
    for identity, _roles in FUNCTION_GRANTS:
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION public.protect_platform_tenant() TO PUBLIC")
    op.execute("DROP VIEW IF EXISTS audit_public_function_execute")
