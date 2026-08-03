"""The billing write moves into the database's decision, not the request's.

THE HOLE

0011 could not gate the `partners` policy on partner_is_active(): the function
reads `partners`, so a policy on `partners` that calls it re-enters itself, and
FORCE RLS guarantees that even for the owner. The workaround was to take the
write away by grant instead -- REVOKE INSERT/UPDATE/DELETE, then GRANT UPDATE
(billing_contact_email) back, because a tenant editing its own billing address
is legitimate.

That one surviving column is outside the gate. Reported live:

    1. request resolves its principal while the partner is active
    2. an operator suspends the partner and commits
    3. the still-open request updates billing_contact_email anyway

Through the HTTP route the request is in practice stopped earlier, because
enforce() reads `memberships` and that table IS gated -- so a suspended
principal loses its grant and gets a 403 before reaching the write. That is
worth stating plainly: the protection is real but incidental. It comes from a
different table's policy, and it would disappear the day anyone gave the
billing route a cheaper authorization check. The database itself does not
refuse the write, which is exactly the arrangement this schema exists to argue
against: one fact -- may this tenant act -- adjudicated by something other than
the database that owns it.

THE SHAPE

A SECURITY DEFINER function narrow enough that owning it grants nothing else,
and the column grant taken away entirely.

SECURITY INVOKER cannot do this. Without the column grant an invoker function
cannot update either; with it, the stale request keeps its bypass. The invoker
version is the same naked UPDATE with a function call wrapped around it.

DEFINER IS NOT A BYPASS HERE, AND THAT IS NOT AN ACCIDENT

db/init creates app_owner with no BYPASSRLS attribute (default NOBYPASSRLS), and
`partners` is FORCE ROW LEVEL SECURITY. So the function body, running as
app_owner, is still subject to partner_self_isolation (`id = <guc>`). The
tenant GUC is transaction-local and the function runs inside the caller's
transaction, so it is still set. The function can reach exactly the row the
caller could already reach -- it just also has to get past the active check,
which the caller could not previously be made to do.

This does not contradict 0011's note that SECURITY DEFINER does not escape the
recursion. That was about calling a partners-reading function from inside the
partners policy. This is a mutation function called from application code; the
policy still does not call partner_is_active(), and the loop is still broken.

WHY THE FUNCTION TAKES NO partner_id

Least privilege is the smaller reason. The load-bearing reason is correctness:

partner_is_active() is SECURITY INVOKER (0011, deliberately). Inside a DEFINER
function the effective user is app_owner, so the function's own read of
`partners` runs as app_owner -- NOBYPASSRLS, FORCE RLS, constrained to
`id = <guc>`. It can therefore only see the row whose id equals the GUC. Passing
in some other partner_id would not raise; it would silently read nothing and
return false, which looks exactly like a correct refusal.

A parameter that turns a wrong answer into a plausible-looking refusal is worse
than no parameter. There isn't one. The tenant comes from the GUC, the same
place every policy in this schema gets it.
"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

FN = "public.set_active_partner_billing_contact(text)"

# Sixth hand-written copy of the tenant expression (0004, 0005, 0006, 0011,
# 0014, here). There is no deployed policy to byte-compare a plpgsql body
# against, so this one is pinned behaviourally instead: a test sets the GUC to
# an active partner, calls the function, and asserts the row actually changed.
# A typo -- a dropped NULLIF, a misspelled GUC name -- makes the function return
# false for everyone, and that test goes red rather than the function quietly
# refusing every caller. Consolidating these into a current_tenant() helper is
# the obvious next move and is not this revision's job.
FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION public.set_active_partner_billing_contact(new_email text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE
    tenant  uuid := NULLIF(pg_catalog.current_setting('app.partner_id', true), '')::uuid;
    updated integer;
BEGIN
    IF tenant IS NULL THEN
        RETURN false;
    END IF;

    -- One statement. The active check and the write cannot be separated by a
    -- commit from anyone else, which is the whole point: the previous version
    -- had no active check at all, and bolting a SELECT in front of the UPDATE
    -- would just move the window rather than close it.
    UPDATE public.partners
       SET billing_contact_email = new_email
     WHERE id = tenant
       AND public.partner_is_active(tenant);

    GET DIAGNOSTICS updated = ROW_COUNT;
    RETURN updated = 1;
END;
$fn$
"""


def upgrade() -> None:
    conn = op.get_bind()

    op.execute(FUNCTION_SQL)

    # Default EXECUTE on a new function is granted to PUBLIC. Left alone, every
    # role in the cluster could call a SECURITY DEFINER function that writes to
    # partners -- the grant this migration is removing would come back through
    # a wider door than the one it left by.
    op.execute(f"REVOKE ALL ON FUNCTION {FN} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FN} TO app_runtime")

    # The column grant 0011 handed back. Everything above exists to make this
    # line survivable.
    op.execute("REVOKE UPDATE (billing_contact_email) ON public.partners FROM app_runtime")

    # --- postflight --------------------------------------------------------
    checks = conn.execute(sa.text(f"""
        SELECT
          (SELECT p.prosecdef FROM pg_proc p
            WHERE p.oid = '{FN}'::regprocedure)                     AS is_definer,
          (SELECT count(*) FROM pg_proc p
             CROSS JOIN LATERAL aclexplode(p.proacl) a
            WHERE p.oid = '{FN}'::regprocedure AND a.grantee = 0)    AS public_grants,
          has_function_privilege('app_runtime', '{FN}'::regprocedure,
                                 'EXECUTE')                          AS runtime_can_call,
          has_any_column_privilege('app_runtime', 'public.partners'::regclass,
                                   'UPDATE')                         AS runtime_can_update
    """)).one()

    problems = []
    if not checks.is_definer:
        problems.append("the function is not SECURITY DEFINER; it cannot write")
    if checks.public_grants:
        # grantee 0 is PUBLIC in an exploded ACL.
        problems.append("PUBLIC still holds a grant on the function")
    if not checks.runtime_can_call:
        problems.append("app_runtime cannot EXECUTE the function; billing is now broken")
    if checks.runtime_can_update:
        # has_any_column_privilege, not has_table_privilege: the grant being
        # removed was column-level, and the table-level function cannot see it.
        problems.append(
            "app_runtime can still UPDATE some column of partners; the REVOKE "
            "did not take effect and the stale-request window is still open")
    if problems:
        raise RuntimeError("0015 postflight:\n  " + "\n  ".join(problems))


def downgrade() -> None:
    op.execute("GRANT UPDATE (billing_contact_email) ON public.partners TO app_runtime")
    op.execute(f"DROP FUNCTION IF EXISTS {FN}")
