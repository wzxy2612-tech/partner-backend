"""transactional outbox for invitation delivery

Audit #5/#10 (the mail-inside-the-savepoint problem).

provision() sent each invitation email INSIDE the batch SAVEPOINT. If row 2
failed, the database rolled back every user and invitation -- but row 1's email
was already gone. The recipient held a token that no longer existed anywhere.
Two-phase onboarding advertises "all or nothing", and that claim was only true
of the half of the world the transaction controls.

An external side effect cannot be rolled back, so it must not be attempted until
the transaction that justifies it has committed. The outbox is the standard
shape: the intent to send is written in the SAME transaction as the invitation,
so the two are atomic together, and delivery is a separate step that reads
committed rows.

WHY THE TOKEN IS ENCRYPTED HERE

invitations stores only sha256(token) -- the plaintext never touches the
database, which is what makes a database leak non-redeemable. Delivery after
commit needs the plaintext back, so something has to carry it across.

Storing it plaintext "just until sent" would undo that property: it would be
readable in the table, in backups, in read replicas, in an operator's ad-hoc
query and in anything that logs a row. Transient plaintext is still persisted
plaintext.

So the outbox carries AEAD ciphertext (AES-256-GCM). A database leak yields
ciphertext; the key lives outside the database. invitations.token_hash remains
the sole authority for redemption -- the outbox never participates in
authentication, it only carries a payload to the mailer.

The AAD binds each ciphertext to its own row:
    outbox_event_id | invitation_id | partner_id | event_type
so a ciphertext copied onto a different event fails authentication instead of
decrypting into someone else's invitation.

After a successful send, the dispatcher nulls token_ciphertext / token_nonce in
the same transaction that marks the row sent. What remains is the audit trail --
which invitation, when, how many attempts, the provider's message id -- with no
recoverable secret.

DELIVERY IS AT-LEAST-ONCE, NOT EXACTLY-ONCE. A mail provider can accept a
message and still fail to return a response, so a retry can duplicate it. That
is acceptable because redemption is a single atomic claim (0011's round): a
second copy of the same invitation email cannot produce a second account.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

MAX_ATTEMPTS = 5


def upgrade() -> None:
    # The composite FK below targets invitations(id, partner_id), and 0007 only
    # created that unique key on users / companies / workflow_templates /
    # workspaces -- invitations was never a parent until now. It has to exist
    # before create_table emits the constraint that references it.
    op.create_unique_constraint(
        "uq_invitations_id_partner", "invitations", ["id", "partner_id"])

    op.create_table(
        "outbox_events",
        sa.Column("id", PGUUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", PGUUID(as_uuid=True), nullable=False),
        sa.Column("invitation_id", PGUUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("recipient", sa.String(320), nullable=False),

        # AEAD payload. Nulled once delivered -- see dispatch().
        sa.Column("token_ciphertext", sa.LargeBinary, nullable=True),
        sa.Column("token_nonce", sa.LargeBinary, nullable=True),
        sa.Column("key_version", sa.Integer, nullable=False, server_default="1"),

        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("provider_message_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),

        # Tenant-composite, consistent with every other cross-row reference in
        # this schema (0007): an outbox event cannot point at another tenant's
        # invitation.
        sa.ForeignKeyConstraint(
            ["invitation_id", "partner_id"], ["invitations.id", "invitations.partner_id"],
            ondelete="CASCADE", name="fk_outbox_events_invitation_id_partner"),
        sa.ForeignKeyConstraint(
            ["partner_id"], ["partners.id"], ondelete="CASCADE",
            name="fk_outbox_events_partner_id"),

        sa.CheckConstraint(
            "status IN ('pending', 'sent', 'failed')",
            name="ck_outbox_events_status_enum"),
        sa.CheckConstraint("attempts >= 0", name="ck_outbox_events_attempts_nonneg"),
        # The secret material and the terminal state are mutually exclusive: a
        # sent event must carry no recoverable token, and a pending one must
        # still have something to send. Enforced rather than left to the
        # dispatcher remembering to clear it.
        sa.CheckConstraint(
            "(status = 'sent') = (token_ciphertext IS NULL AND sent_at IS NOT NULL)",
            name="ck_outbox_events_sent_has_no_secret"),
    )

    op.create_index("ix_outbox_events_partner_id", "outbox_events", ["partner_id"])
    # The dispatcher's claim query: pending rows whose backoff has elapsed,
    # oldest first.
    op.execute(
        "CREATE INDEX ix_outbox_events_claimable ON outbox_events "
        "(available_at) WHERE status = 'pending'")



def downgrade() -> None:
    op.drop_table("outbox_events")
    op.drop_constraint("uq_invitations_id_partner", "invitations", type_="unique")
