"""app_dispatcher: cross-tenant delivery without a cross-tenant role.

WHY A FOURTH ROLE

The outbox has no dispatcher. There is no worker, no endpoint, no CLI and no
compose service, so /onboarding/commit writes a pending event that nothing ever
sends -- invited users stay inactive and never receive a token. Closing that
means deciding which role does the sending, and the tempting answer is
app_platform, which already exists and can already see everything.

That is the wrong answer for a reason that is about processes, not roles: a
dispatcher is a small program with one job, and giving it app_platform would
mean a compromise of that program yields BYPASSRLS over the entire database.
The blast radius of the smallest component should not be the largest one.

WHAT NOBYPASSRLS ACTUALLY BUYS HERE, STATED HONESTLY

app_dispatcher does need to see other tenants' rows -- that is its entire
function. It gets that from three policies below, each `USING (true)` for this
role and this table.

`USING (true) TO app_dispatcher` IS BYPASSRLS FOR THAT TABLE. Calling it
anything else would be dishonest. What it buys is that the bypass is per table
and opted into one at a time: the role attribute would grant it on every table
that exists and every table added later, which is precisely how outbox_events
shipped world-writable. Here, a new table is unreachable until someone writes a
policy naming this role, and tests/test_rls_coverage.py refuses any
permissive-true policy that is not registered with a reason.

Three tables, and the reason each is needed:

  outbox_events  claim the work, read the sealed payload, record the outcome
  invitations    is this invitation still pending and unexpired
  partners       partner_is_active() reads it, and that function is SECURITY
                 INVOKER, so it runs as whoever called it

That last one is the trap. Without a policy on `partners`, partner_is_active()
called by this role reads nothing and returns false for every partner -- so the
claim would match no rows, silently, forever. The dispatcher would be installed,
running, reporting success, and delivering nothing: exactly the symptom it was
built to fix.

WHAT IS NOT WIDENED

app_runtime's grants on outbox_events are unchanged in this revision. Narrowing
them to insert-only is the right end state and moves roughly fourteen tests --
some of which change meaning rather than location, because "A reads zero of B's
rows" becomes "A may not read the table at all". That belongs in its own
revision, after the dispatcher's real needs are established by working code
rather than by this docstring's guesses.
"""
import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

ROLE = "app_dispatcher"

# Columns the dispatcher may write on outbox_events: the outcome of an attempt,
# and the secret material it is responsible for destroying.
#
# NOT partner_id, invitation_id, event_type, recipient or key_version. The
# policy below is USING (true), so nothing in row security would stop this role
# from moving an event to another tenant or redirecting it -- the column grant
# is what does. That division is deliberate: the policy answers "which rows",
# the grant answers "which facts about them", and neither is asked to do the
# other's job.
WRITABLE = ["status", "attempts", "available_at", "last_error",
            "provider_message_id", "sent_at", "token_ciphertext", "token_nonce"]

# Read-only, column-scoped. token_hash is deliberately absent: the dispatcher
# has no use for it and it is the value that makes a leaked invitations row
# redeemable.
INVITATION_COLUMNS = ["id", "partner_id", "status", "expires_at"]

# Exactly what partner_is_active() reads.
PARTNER_COLUMNS = ["id", "status"]

POLICIES = [
    ("outbox_events", "dispatcher_claims_any_tenant", "FOR SELECT", "USING (true)"),
    ("outbox_events", "dispatcher_records_outcome", "FOR UPDATE",
     "USING (true) WITH CHECK (true)"),
    ("invitations", "dispatcher_checks_validity", "FOR SELECT", "USING (true)"),
    ("partners", "dispatcher_checks_active_state", "FOR SELECT", "USING (true)"),
]


def upgrade() -> None:
    conn = op.get_bind()

    # --- preflight ---------------------------------------------------------
    role = conn.execute(sa.text(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :r"),
        {"r": ROLE}).one_or_none()
    if role is None:
        raise RuntimeError(
            f"0018 preflight: role {ROLE} does not exist. It is provisioned by "
            f"an operator, not by a migration -- app_owner is NOCREATEROLE on "
            f"purpose, so that reviewing a schema change is not also reviewing "
            f"who may connect to the database.\n"
            f"Run: docker compose exec -T db psql -U postgres -d "
            f"partner_backend < scripts/provision_dispatcher_role.sql")
    if role.rolsuper or role.rolbypassrls:
        raise RuntimeError(
            f"0018 preflight: {ROLE} is SUPERUSER or BYPASSRLS. The policies "
            f"this migration creates would then be decoration -- row security "
            f"would not apply to it at all, and every isolation test about it "
            f"would pass while asserting nothing. Fix the role first:\n"
            f"  ALTER ROLE {ROLE} NOSUPERUSER NOBYPASSRLS;")

    # --- grants ------------------------------------------------------------
    op.execute(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
    op.execute(f"GRANT SELECT ON outbox_events TO {ROLE}")
    op.execute(f"GRANT UPDATE ({', '.join(WRITABLE)}) ON outbox_events TO {ROLE}")
    op.execute(f"GRANT SELECT ({', '.join(INVITATION_COLUMNS)}) "
               f"ON invitations TO {ROLE}")
    op.execute(f"GRANT SELECT ({', '.join(PARTNER_COLUMNS)}) ON partners TO {ROLE}")

    # --- policies ----------------------------------------------------------
    for table, name, command, clause in POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")
        op.execute(f"CREATE POLICY {name} ON {table} {command} TO {ROLE} {clause}")

    # --- postflight --------------------------------------------------------
    #
    # The negative checks are the ones worth having. A missing policy shows up
    # loudly the first time the dispatcher runs; a grant that is wider than
    # intended shows up never.
    checks = conn.execute(sa.text("""
        SELECT
          has_column_privilege(:r, 'public.outbox_events'::regclass,
                               'partner_id', 'UPDATE')      AS can_move_tenant,
          has_column_privilege(:r, 'public.outbox_events'::regclass,
                               'recipient', 'UPDATE')       AS can_redirect,
          has_any_column_privilege(:r, 'public.invitations'::regclass,
                                   'UPDATE')                AS can_write_invites,
          has_any_column_privilege(:r, 'public.partners'::regclass,
                                   'UPDATE')                AS can_write_partners,
          has_column_privilege(:r, 'public.invitations'::regclass,
                               'token_hash', 'SELECT')      AS can_read_token_hash,
          has_column_privilege(:r, 'public.outbox_events'::regclass,
                               'status', 'UPDATE')          AS can_record_outcome,
          has_table_privilege (:r, 'public.outbox_events'::regclass,
                               'SELECT')                    AS can_claim,
          (SELECT count(*) FROM pg_policies
            WHERE schemaname = 'public'
              AND :r = ANY(roles))                          AS policy_count
    """), {"r": ROLE}).one()

    problems = []
    if checks.can_move_tenant:
        problems.append("can UPDATE outbox_events.partner_id -- it could move an "
                        "event to another tenant, and USING (true) would allow it")
    if checks.can_redirect:
        problems.append("can UPDATE outbox_events.recipient -- it could redirect "
                        "an invitation token to any address")
    if checks.can_write_invites:
        problems.append("can write invitations; it only needs to read validity")
    if checks.can_write_partners:
        problems.append("can write partners; it only needs the active state")
    if checks.can_read_token_hash:
        problems.append("can read invitations.token_hash, which it has no use for")
    if not checks.can_record_outcome or not checks.can_claim:
        problems.append("cannot claim or record an outcome; delivery is broken")
    if checks.policy_count != len(POLICIES):
        problems.append(
            f"{checks.policy_count} of {len(POLICIES)} policies name this role; "
            f"a missing one means it reads zero rows from that table SILENTLY")
    if problems:
        raise RuntimeError(f"0018 postflight: {ROLE}\n  " + "\n  ".join(problems))


def downgrade() -> None:
    for table, name, _command, _clause in POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")
    op.execute(f"REVOKE ALL ON outbox_events FROM {ROLE}")
    op.execute(f"REVOKE ALL ON invitations FROM {ROLE}")
    op.execute(f"REVOKE ALL ON partners FROM {ROLE}")
