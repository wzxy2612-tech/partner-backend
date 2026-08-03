"""The outbox state machine, stated as constraints instead of as habits.

WHAT 0013 ACTUALLY ENFORCED

    CHECK ((status = 'sent') = (token_ciphertext IS NULL AND sent_at IS NOT NULL))

Read it for the `failed` case. Left side is false, so the right side must be
false -- which a row satisfies by keeping its ciphertext. A dead-lettered event
was therefore free to retain a fully recoverable invitation token, and the only
thing clearing it was application code choosing to. Reported live:

    failed_event_retains_recoverable_payload: ('failed', True, True)

`token_nonce` appears nowhere in that constraint at all, for any status.

WHY THIS MIGRATION TURNS FORCE OFF, AND WHY THAT IS NOT THE LAZY OPTION

outbox_events is FORCE ROW LEVEL SECURITY (0014) and app_owner is NOBYPASSRLS,
so a migration that just runs UPDATE here matches zero rows and reports success.
0014's docstring warned whoever wrote this revision about exactly that.

The obvious remedy -- loop over partners, SET LOCAL app.partner_id, clean each
tenant's rows under its own scope -- does not work, and fails in the worst
possible direction. The policy is

    partner_id = <guc> AND partner_is_active(<guc>)

Both conjuncts. Setting the GUC to a SUSPENDED partner still yields no rows, and
suspended partners are precisely where stale pending events accumulated before
0015 began revoking their invitations. A per-tenant loop would run clean, report
a plausible number, and leave the most exposed rows untouched.

So FORCE is lifted for the length of this transaction. ALTER TABLE takes an
ACCESS EXCLUSIVE lock, so no other session observes the window, and alembic runs
the whole migration inside one transaction -- a failure anywhere below rolls the
DDL back with everything else. FORCE is asserted back on before this returns.

WHAT IS REPAIRED AND WHAT IS REFUSED

Repaired: terminal rows (sent, failed) still holding ciphertext or nonce. This
deletes a dead secret. The token is already unusable -- the event was
dead-lettered or its invitation was revoked, accepted or expired -- so nothing
is lost that anyone could want, and what remains is a liability.

Refused: anything else. A pending row with no payload, a pending row with
sent_at, a failed row with sent_at -- these are state-machine inconsistencies
where the correct value is a judgment about what happened, and picking one
invents history. That is the same line 0012 drew for cross-company parent
chains: the migration refuses and points at a read-only scan
(scripts/scan_outbox_invariants.sql) instead of guessing.

Clearing a dead secret removes something. Setting a state invents something.

ONE CONSEQUENCE WORTH STATING

`failed => sent_at IS NULL` forecloses a future "delivered, then bounced" state.
That is a real narrowing and it is deliberate for now: no code produces such a
row, and a constraint that permits states nothing creates is a constraint that
describes nothing. Bounce handling would revise this, on purpose, in its own
revision.
"""
import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

OLD_CHECK = "ck_outbox_events_sent_has_no_secret"

# Three constraints, not one. This codebase matches on diag.constraint_name
# rather than parsing error text, so which invariant broke should be a fact the
# database reports rather than something a caller reconstructs from a message.
CHECKS = {
    "ck_outbox_pending_has_payload":
        "status <> 'pending' OR (token_ciphertext IS NOT NULL "
        "AND token_nonce IS NOT NULL AND sent_at IS NULL)",
    "ck_outbox_sent_is_clean":
        "status <> 'sent' OR (token_ciphertext IS NULL "
        "AND token_nonce IS NULL AND sent_at IS NOT NULL)",
    "ck_outbox_failed_is_clean":
        "status <> 'failed' OR (token_ciphertext IS NULL "
        "AND token_nonce IS NULL AND sent_at IS NULL)",
}

# Inconsistencies this migration will not invent a resolution for. Each is
# (label, predicate).
REFUSALS = [
    ("pending with no payload",
     "status = 'pending' AND (token_ciphertext IS NULL OR token_nonce IS NULL)"),
    ("pending already marked delivered",
     "status = 'pending' AND sent_at IS NOT NULL"),
    ("failed carrying a delivery timestamp",
     "status = 'failed' AND sent_at IS NOT NULL"),
    ("sent with no delivery timestamp",
     "status = 'sent' AND sent_at IS NULL"),
]


def upgrade() -> None:
    conn = op.get_bind()

    # See the module docstring. Lifted for this transaction only; a per-partner
    # GUC loop cannot reach suspended partners' rows, which is where the stale
    # payloads are.
    op.execute("ALTER TABLE outbox_events NO FORCE ROW LEVEL SECURITY")

    # --- refuse before repairing ------------------------------------------
    #
    # Order matters: the repair below would otherwise mask a row that is BOTH
    # secret-carrying and state-inconsistent, leaving the second problem to be
    # discovered by the constraint at the end with no context about it.
    blocked = []
    for label, predicate in REFUSALS:
        rows = conn.execute(sa.text(
            f"SELECT id FROM outbox_events WHERE {predicate} "
            f"ORDER BY id LIMIT 20")).scalars().all()
        if rows:
            total = conn.execute(sa.text(
                f"SELECT count(*) FROM outbox_events WHERE {predicate}"
            )).scalar_one()
            blocked.append(f"{label}: {total} row(s), e.g. "
                           f"{[str(r) for r in rows[:5]]}")
    if blocked:
        raise RuntimeError(
            "0017 preflight: outbox_events holds rows whose state this "
            "migration will not guess at.\n  " + "\n  ".join(blocked) +
            "\nRun scripts/scan_outbox_invariants.sql, decide what each row "
            "should be, and fix them explicitly. Ids are safe to share; the "
            "payloads are not.")

    # --- repair: terminal rows must not keep a dead secret -----------------
    cleared = conn.execute(sa.text(
        "UPDATE outbox_events "
        "   SET token_ciphertext = NULL, token_nonce = NULL "
        " WHERE status IN ('sent', 'failed') "
        "   AND (token_ciphertext IS NOT NULL OR token_nonce IS NOT NULL) "
        "RETURNING id")).scalars().all()
    if cleared:
        print(f"0017: cleared recoverable payloads from {len(cleared)} "
              f"terminal outbox event(s)")

    # --- the invariants ----------------------------------------------------
    op.execute(f"ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS {OLD_CHECK}")
    for name, expression in CHECKS.items():
        op.execute(f"ALTER TABLE outbox_events ADD CONSTRAINT {name} "
                   f"CHECK ({expression})")

    op.execute("ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY")

    # --- postflight --------------------------------------------------------
    #
    # The FORCE check is the one that matters: everything above is pointless if
    # this migration is also the thing that quietly left the table readable to
    # its owner across every tenant.
    state = conn.execute(sa.text("""
        SELECT c.relforcerowsecurity AS forced,
               (SELECT count(*) FROM pg_constraint k
                 WHERE k.conrelid = c.oid AND k.contype = 'c'
                   AND k.conname = ANY(:names))          AS added,
               (SELECT count(*) FROM pg_constraint k
                 WHERE k.conrelid = c.oid AND k.conname = :old) AS old_left
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'outbox_events'
    """), {"names": list(CHECKS), "old": OLD_CHECK}).one()

    problems = []
    if not state.forced:
        problems.append(
            "FORCE ROW LEVEL SECURITY was not restored -- the owner can read "
            "and write across every tenant on this table")
    if state.added != len(CHECKS):
        problems.append(
            f"{state.added} of {len(CHECKS)} invariants are present")
    if state.old_left:
        problems.append(
            f"{OLD_CHECK} survived; two constraints now encode overlapping "
            f"rules about the same rows")
    if problems:
        raise RuntimeError("0017 postflight:\n  " + "\n  ".join(problems))


def downgrade() -> None:
    for name in CHECKS:
        op.execute(f"ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS {name}")
    op.execute(
        f"ALTER TABLE outbox_events ADD CONSTRAINT {OLD_CHECK} "
        f"CHECK ((status = 'sent') = "
        f"(token_ciphertext IS NULL AND sent_at IS NOT NULL))")
