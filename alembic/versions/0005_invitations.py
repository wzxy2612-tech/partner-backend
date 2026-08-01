"""invitations for CSV-onboarded users

An onboarded user is created inactive with no password; an invitation carries a
one-time token they redeem to set a password and activate. Partner-owned, so RLS
is ENABLE + FORCE keyed on partner_id -- using the hardened NULLIF form from 0004
so an empty tenant GUC fails closed rather than erroring.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        "invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_invitations_partner_id", "invitations", ["partner_id"])

    op.execute("ALTER TABLE invitations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE invitations FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY partner_isolation ON invitations "
        f"USING (partner_id = {GUC}) WITH CHECK (partner_id = {GUC})"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS partner_isolation ON invitations")
    op.drop_index("ix_invitations_partner_id", table_name="invitations")
    op.drop_table("invitations")
