"""The runtime path may queue mail and nothing else.

WHAT IT HELD UNTIL NOW

`ALTER DEFAULT PRIVILEGES` (db/init/00-roles.sql:35) grants SELECT, INSERT,
UPDATE and DELETE on every table app_owner creates, so app_runtime got the full
set on outbox_events the moment 0013 created it -- and, with no row security
until 0014, that was the cross-tenant redirect: Partner A rewriting Partner B's
`recipient` and having the dispatcher mail B's token to an address of A's
choosing.

0014 scoped those grants to the tenant's own rows. This removes them.

WHY IT WAITED FOR 0018

Tightening this needed the answer to "then who reads the table?", and until the
dispatcher existed that answer was a guess. Moving a privilege boundary twice is
how half-fixes happen, so the boundary moved once, after app_dispatcher was
running and its real needs were established by working code.

WHAT IS LEFT, AND WHY EVEN THE INSERT IS COLUMN-SCOPED

    id, partner_id, invitation_id, event_type, recipient,
    token_ciphertext, token_nonce, key_version

`status` and `available_at` are NOT granted, and enqueue_invitation stopped
naming them: both carry server defaults ('pending', now()). A tenant therefore
cannot express a non-pending or future-dated event -- not "is prevented from",
but has no column to write it through. `attempts`, `last_error`, `sent_at` and
`provider_message_id` describe what a dispatcher did and were never the
runtime's to state.

WHAT THIS COSTS, STATED PLAINLY

The USING half of `partner_isolation` on outbox_events is now dormant. No role
evaluates it: app_runtime cannot read or update the table at all, app_dispatcher
reads through its own `USING (true)` policy, and app_platform is BYPASSRLS. Only
the WITH CHECK half still bites, on insert.

That is a real loss of evidence and it is the honest trade. The alternative --
keeping a SELECT grant so the clause stays observable -- means holding a
privilege no application code uses, which the next audit would flag as an unused
grant, and "we keep it so a test can watch it" is a justification that decays.
The clause stays because the day someone adds "show me whether my invitation
was sent", the grant that makes it live is one line and the policy behind it is
already correct. tests/test_rls_coverage.py is what keeps it correct meanwhile.
"""
import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

ROLE = "app_runtime"

INSERTABLE = ["id", "partner_id", "invitation_id", "event_type", "recipient",
              "token_ciphertext", "token_nonce", "key_version"]

# Columns the runtime must NOT be able to state. Checked individually in the
# postflight rather than inferred from the grant, because "we granted a list"
# and "nothing outside the list is reachable" are different claims and only the
# second one matters.
FORBIDDEN = ["status", "available_at", "attempts", "last_error", "sent_at",
             "provider_message_id"]


def upgrade() -> None:
    conn = op.get_bind()

    op.execute(f"REVOKE ALL ON outbox_events FROM {ROLE}")
    op.execute(f"GRANT INSERT ({', '.join(INSERTABLE)}) ON outbox_events TO {ROLE}")

    # --- postflight --------------------------------------------------------
    reach = conn.execute(sa.text("""
        SELECT has_any_column_privilege(:r, 'public.outbox_events'::regclass,
                                        'SELECT')            AS can_read,
               has_any_column_privilege(:r, 'public.outbox_events'::regclass,
                                        'UPDATE')            AS can_update,
               has_table_privilege     (:r, 'public.outbox_events'::regclass,
                                        'DELETE')            AS can_delete
    """), {"r": ROLE}).one()

    problems = []
    if reach.can_read:
        problems.append("can still SELECT outbox_events")
    if reach.can_update:
        problems.append("can still UPDATE outbox_events -- the reported "
                        "cross-tenant redirect used exactly this")
    if reach.can_delete:
        problems.append("can still DELETE outbox_events")

    for column in FORBIDDEN:
        if conn.execute(sa.text(
            "SELECT has_column_privilege(:r, 'public.outbox_events'::regclass, "
            "                            :c, 'INSERT')"),
                {"r": ROLE, "c": column}).scalar_one():
            problems.append(f"can INSERT outbox_events.{column}")

    for column in INSERTABLE:
        if not conn.execute(sa.text(
            "SELECT has_column_privilege(:r, 'public.outbox_events'::regclass, "
            "                            :c, 'INSERT')"),
                {"r": ROLE, "c": column}).scalar_one():
            problems.append(
                f"cannot INSERT outbox_events.{column} -- onboarding is broken")

    if problems:
        raise RuntimeError(f"0019 postflight: {ROLE}\n  " + "\n  ".join(problems))


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON outbox_events FROM {ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON outbox_events TO {ROLE}")
