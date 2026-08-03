"""outbox_events row security, and the migration bookkeeping table.

WHAT WENT WRONG

0013 created outbox_events and stopped. It never ran ENABLE ROW LEVEL SECURITY,
so the table shipped with no tenant boundary at all -- and because
db/init/00-roles.sql:35 hands app_runtime SELECT/INSERT/UPDATE/DELETE on every
table app_owner creates, "no boundary" did not mean "unreachable". It meant any
tenant could read, rewrite and delete any other tenant's queued mail. Reported
live: Partner A ran

    UPDATE outbox_events SET recipient = 'attacker@...' WHERE id = <B's event>

and the dispatcher then decrypted B's invitation token and delivered it to the
attacker. Cross-tenant account takeover, from one missing DDL statement.

This is the fail-open direction of the default-privilege design: creating a
table and protecting a table are two separate acts, and only the first one is
required to happen. tests/test_rls_coverage.py now enumerates from privileges
rather than from pg_policies so that the *absence* of a policy is a visible
state rather than an empty result set.

SCOPE OF THIS MIGRATION -- READ BEFORE WIDENING IT

Row security only. app_runtime keeps the grants it holds today.

That is deliberate and temporary. The right end state is runtime insert-only
(ideally not even a bare INSERT, but a controlled enqueue function), with
reads, claims, retries and secret-clearing belonging to whatever role runs the
dispatcher. But no dispatcher exists yet -- there is no worker, no endpoint, no
CLI, no compose service -- so the role that needs SELECT on this table has not
been chosen. Tightening grants now means choosing the wall before choosing
where the door goes, and moving a privilege boundary twice is how you get a
half-fix.

    DEFERRED: tighten app_runtime on outbox_events to insert-only, once the
    dispatcher's role is decided (dedicated app_dispatcher vs app_platform vs
    a SECURITY DEFINER dispatch function).

Nothing is left unguarded in the meantime: the policy below scopes every one of
those grants to the tenant's own rows, which is what closed the redirect.

WHAT THIS MIGRATION DOES *NOT* CLOSE

The dispatcher and the redemption path run as app_platform, which is BYPASSRLS.
Every guarantee expressed only as a policy is absent there by construction. The
claim query still selects expired invitations, and redemption still accepts
tokens belonging to suspended partners. Those are joins, not policies, and they
are not in this revision.

A NOTE FOR WHOEVER WRITES 0015

After this migration outbox_events is FORCE RLS, and app_owner is not exempt.
A migration that tries to repair existing rows -- say, clearing ciphertext off
terminal events for a tightened CHECK constraint -- will match zero rows and
report success, because no GUC is set and `partner_id = NULL` is NULL. This
project has been bitten by that three times. Do the data work before enabling,
or set the GUC per partner, or do it in a revision that runs first.
"""
import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

# The predicate is written out literally rather than derived at runtime, so that
# reading this file tells you the end state. It is then compared against a table
# that already carries the deployed predicate -- see the postflight. Literal for
# determinism, catalog comparison for drift.
GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"
PREDICATE = f"partner_id = {GUC} AND partner_is_active({GUC})"

# Any already-gated partner-owned table works; invitations is the one
# outbox_events hangs off, so if that policy is wrong this table's is moot.
REFERENCE_TABLE = "invitations"

# app_runtime has no business in the migration ledger. alembic_version carries
# no partner_id, so no policy can scope it; the only correct grant is none.
# This is unrelated to the outbox and does not wait on the dispatcher decision.
BOOKKEEPING = "alembic_version"


def upgrade() -> None:
    conn = op.get_bind()

    # --- preflight ---------------------------------------------------------
    existing = conn.execute(sa.text("""
        SELECT policyname FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'outbox_events'
    """)).scalars().all()
    if existing:
        raise RuntimeError(
            f"0014 preflight: outbox_events already carries policies {existing}. "
            f"This revision assumes it has none and would clobber them. Reconcile "
            f"by hand before proceeding.")

    ref = conn.execute(sa.text("""
        SELECT coalesce(qual, '') AS qual, coalesce(with_check, '') AS with_check
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = :t
          AND policyname = 'partner_isolation'
    """), {"t": REFERENCE_TABLE}).one_or_none()
    if ref is None:
        raise RuntimeError(
            f"0014 preflight: no partner_isolation policy on {REFERENCE_TABLE}. "
            f"There is nothing to compare the new policy against, so the check "
            f"that this migration did not typo the predicate cannot run.")
    if "partner_is_active" not in ref.qual or "partner_is_active" not in ref.with_check:
        raise RuntimeError(
            f"0014 preflight: the {REFERENCE_TABLE} policy is not gated on "
            f"partner_is_active. Copying its shape would propagate that gap.")

    # --- row security ------------------------------------------------------
    op.execute("ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY partner_isolation ON outbox_events "
        f"USING ({PREDICATE}) WITH CHECK ({PREDICATE})")

    # --- postflight: the fifth copy of GUC must equal the other four --------
    #
    # This literal is the fifth hand-written copy of the tenant predicate in
    # alembic/versions. A typo in it -- dropping the NULLIF that 0004 added, say
    # -- would leave this table looking gated to every text-matching check while
    # behaving differently from the other twelve. The catalog deparses both
    # policies through the same printer, so byte equality is a real comparison
    # and not a comparison of two strings this file wrote.
    got = conn.execute(sa.text("""
        SELECT coalesce(qual, '') AS qual, coalesce(with_check, '') AS with_check
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'outbox_events'
          AND policyname = 'partner_isolation'
    """)).one()
    if (got.qual, got.with_check) != (ref.qual, ref.with_check):
        raise RuntimeError(
            "0014 postflight: the outbox_events policy does not deparse to the "
            f"same expression as {REFERENCE_TABLE}.\n"
            f"  {REFERENCE_TABLE}.qual:       {ref.qual}\n"
            f"  outbox_events.qual:  {got.qual}\n"
            f"  {REFERENCE_TABLE}.with_check: {ref.with_check}\n"
            f"  outbox_events.with_check: {got.with_check}")

    # --- migration bookkeeping ---------------------------------------------
    op.execute(f"REVOKE ALL ON {BOOKKEEPING} FROM app_runtime")

    # Column-level grants survive a table-level REVOKE in PostgreSQL, so the
    # check uses the same privilege functions the coverage guard does rather
    # than assuming ALL meant all.
    still_held = conn.execute(sa.text("""
        SELECT has_any_column_privilege('app_runtime', :t, 'SELECT')
            OR has_any_column_privilege('app_runtime', :t, 'INSERT')
            OR has_any_column_privilege('app_runtime', :t, 'UPDATE')
            OR has_table_privilege     ('app_runtime', :t, 'DELETE')
    """), {"t": BOOKKEEPING}).scalar_one()
    if still_held:
        raise RuntimeError(
            f"0014 postflight: app_runtime can still reach {BOOKKEEPING} after "
            f"REVOKE ALL. Check for column-level grants.")


def downgrade() -> None:
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {BOOKKEEPING} TO app_runtime")
    op.execute("DROP POLICY IF EXISTS partner_isolation ON outbox_events")
    op.execute("ALTER TABLE outbox_events NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE outbox_events DISABLE ROW LEVEL SECURITY")
