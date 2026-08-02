"""RLS active-state gate: a suspended partner's runtime path stops writing

Audit #2 (TOCTOU). Identity is resolved in one transaction and the business
operation runs in another:

    get_principal()      -> platform_session() ... transaction ENDS
    <window>             -> suspend_partner(A) can commit here
    handler              -> session_for_principal() opens a NEW transaction

An in-flight request that authenticated a millisecond before the suspend still
completed its writes. Re-checking `principal.is_suspended` inside the handler
does not close this either -- it only moves the window, because the check and
the write are still two separate statements and the suspend can land between
them. Any fix that lives in application code is racing the same race.

So the check moves to where it cannot be raced: into the RLS policy itself,
evaluated by the database as part of every statement the runtime path issues.
After a suspend commits, the very next SQL statement from the in-flight request
sees zero rows and writes nothing. The request does not need to notice; it
cannot succeed.

Shape:
  * partner_is_active(uuid) -- one STABLE function holding the definition of
    "may this tenant act". Twelve policies call it rather than each spelling out
    a status comparison. Twelve copies of a predicate is twelve things to
    forget to update; this is the same "share the definition" rule the schema
    already applies to tenancy.
  * Every partner_isolation policy becomes
        partner_id = <guc> AND partner_is_active(<guc>)
    and partners' self policy likewise.
  * The function is SECURITY INVOKER and partners keeps its ungated `id = GUC`
    policy. Both details are load-bearing. Gating the partners policy with this
    function makes reading partners re-enter its own policy -- unbounded
    recursion, which FORCE RLS guarantees even for the owner, so SECURITY
    DEFINER does not escape it. Under the ungated policy the caller reads
    exactly the row it is asking about, which is all the function needs.
  * The write that gating would have blocked (a suspended tenant setting its own
    status back to 'active') is blocked by revoking INSERT/UPDATE/DELETE on
    partners from app_runtime instead. The lifecycle belongs to the platform
    path; the runtime path never needed write access here.

Not affected:
  * app_platform (BYPASSRLS) -- suspend, activate, purge and the retention jobs
    keep working while a partner is suspended. That is required: otherwise
    suspending a partner would lock out the operator who has to un-suspend it.
  * users / sessions keep ENABLE-without-FORCE, so authentication (platform
    path) still resolves a suspended partner's principal; get_principal turns
    that into a clean 403 instead of a confusing empty result.

This is defence in depth, not a replacement for the application check. The 403
comes from deps.py so the caller gets a meaningful status; the database
guarantees that a caller who slips past the 403 still cannot write.
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"

# Every table carrying partner_isolation keyed on partner_id, across 0002-0006.
# Assembled here as one list precisely because the policies were created in five
# different migrations; a table missing from this list keeps a policy with no
# active-state condition, which is a silent bypass.
PARTNER_ID_TABLES = [
    "companies", "memberships", "partner_activity_log",   # 0002
    "users", "sessions",                                   # 0002/0003 (ENABLE only)
    "workspaces",                                          # 0003
    "invitations",                                         # 0005
    "connectors", "workflow_templates", "workflows",       # 0006
    "token_usage", "threads",                              # 0006
]


def upgrade() -> None:
    conn = op.get_bind()

    # Preflight: the list above must match what is actually in pg_policies, or
    # a table silently keeps an ungated policy. Fail rather than half-apply.
    rows = conn.execute(sa.text("""
        SELECT tablename FROM pg_policies
        WHERE schemaname = 'public' AND policyname = 'partner_isolation'
        ORDER BY tablename
    """)).scalars().all()
    actual, expected = set(rows), set(PARTNER_ID_TABLES)
    if actual != expected:
        raise RuntimeError(
            "0011 preflight: the partner_isolation policy inventory does not "
            "match this migration's list. Tables with a policy this migration "
            f"would NOT gate: {sorted(actual - expected)}. Listed but having no "
            f"policy: {sorted(expected - actual)}. Reconcile before applying -- "
            "an ungated table is a suspended partner that can still write.")

    # One definition of "may this tenant act", shared by every policy.
    op.execute("""
        CREATE OR REPLACE FUNCTION partner_is_active(pid uuid)
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY INVOKER
        SET search_path = public
        AS $$
            SELECT EXISTS (
                SELECT 1 FROM partners
                WHERE id = pid AND status = 'active'
            );
        $$;
    """)
    # The runtime role must be able to call it; it must NOT be able to redefine
    # it (ownership stays with the migration owner).
    op.execute("GRANT EXECUTE ON FUNCTION partner_is_active(uuid) TO app_runtime")

    for table in PARTNER_ID_TABLES:
        op.execute(f"DROP POLICY IF EXISTS partner_isolation ON {table}")
        op.execute(
            f"CREATE POLICY partner_isolation ON {table} "
            f"USING (partner_id = {GUC} AND partner_is_active({GUC})) "
            f"WITH CHECK (partner_id = {GUC} AND partner_is_active({GUC}))")

    # partners keeps its ungated `id = GUC` policy, and MUST.
    #
    # Gating it would make the policy call a function whose body reads partners,
    # so every read of the table re-enters its own policy -- unbounded recursion
    # ("stack depth limit exceeded"). SECURITY DEFINER does not help: partners is
    # FORCE RLS, so the owner is subject to the policy too, which is exactly the
    # property that makes FORCE worth having.
    #
    # Leaving it ungated would normally reopen a hole: app_runtime holds UPDATE
    # on every table by default privilege, and the policy only checks `id`, so a
    # suspended tenant could run
    #     UPDATE partners SET status = 'active' WHERE id = <own>
    # and un-suspend itself -- reachable by exactly the in-flight request this
    # migration exists to stop. That hole predates this migration.
    #
    # It is closed by taking the write away instead of by policy: the partner
    # lifecycle is a platform-path concern (suspend/activate/purge all run as
    # app_platform), so the runtime role has no business writing this table at
    # all. SELECT stays -- the tenant may read its own row, and partner_is_active
    # needs that read to work under the `id = GUC` policy.
    # Column-level, not table-level.
    #
    # The tenant legitimately self-serves ONE column here: billing_contact_email
    # (P4). What it must not touch is the lifecycle -- status, suspended_at,
    # suspension_retention_until -- because an ungated partners policy checks
    # only `id`, so a blanket UPDATE grant would let a suspended tenant run
    #     UPDATE partners SET status = 'active' WHERE id = <own>
    # and walk out of its own suspension.
    #
    # Revoking UPDATE on the whole table (my first attempt) also killed the
    # billing-contact endpoint. The rule being enforced is "the runtime path may
    # not drive the lifecycle", and that rule is about specific COLUMNS, so the
    # grant has to be about specific columns too. INSERT/DELETE stay revoked
    # outright: creating or destroying partners is never a tenant action.
    op.execute("REVOKE INSERT, UPDATE, DELETE ON partners FROM app_runtime")
    op.execute("GRANT UPDATE (billing_contact_email) ON partners TO app_runtime")

    # State the partners policy explicitly rather than relying on "we did not
    # touch it". Recreating it to the ungated form makes this migration's end
    # state deterministic no matter what an earlier migration left behind, and
    # it documents the constraint in the one place that enforces it.
    op.execute("DROP POLICY IF EXISTS partner_self_isolation ON partners")
    op.execute(
        f"CREATE POLICY partner_self_isolation ON partners "
        f"USING (id = {GUC}) WITH CHECK (id = {GUC})")

    # Fail closed if the loop was ever reintroduced: no policy on partners may
    # call the function whose body reads partners.
    bad = conn.execute(sa.text("""
        SELECT policyname FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'partners'
          AND (coalesce(qual, '') || coalesce(with_check, '')) LIKE '%partner_is_active%'
    """)).scalars().all()
    if bad:
        raise RuntimeError(
            f"0011: policies {bad} on `partners` reference partner_is_active, "
            f"whose body reads `partners`. Every read of the table would "
            f"re-enter its own policy -- unbounded recursion. partners must "
            f"stay ungated; the write it would have blocked is revoked instead.")


def downgrade() -> None:
    for table in PARTNER_ID_TABLES:
        op.execute(f"DROP POLICY IF EXISTS partner_isolation ON {table}")
        op.execute(
            f"CREATE POLICY partner_isolation ON {table} "
            f"USING (partner_id = {GUC}) WITH CHECK (partner_id = {GUC})")
    # partner_self_isolation is not touched by upgrade(), so it is not touched
    # here either -- recreating it would leave a state upgrade() never set.
    # Restoring the grant does reopen self-reactivation; that is what the
    # pre-0011 schema had.
    op.execute("REVOKE UPDATE (billing_contact_email) ON partners FROM app_runtime")
    op.execute("GRANT INSERT, UPDATE, DELETE ON partners TO app_runtime")
    op.execute("REVOKE EXECUTE ON FUNCTION partner_is_active(uuid) FROM app_runtime")
    op.execute("DROP FUNCTION IF EXISTS partner_is_active(uuid)")
