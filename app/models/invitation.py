import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, ForeignKey, ForeignKeyConstraint,
                        CheckConstraint, Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Invitation(Base):
    """One-time invite for an onboarded user. Redeeming it sets the user's
    password and activates them. Status: pending / accepted / revoked."""
    __tablename__ = "invitations"
    __table_args__ = (
        Index("ix_invitations_partner_id", "partner_id"),
        # 0013: target for the outbox event's tenant-composite FK.
        UniqueConstraint("id", "partner_id", name="uq_invitations_id_partner"),
        ForeignKeyConstraint(
            ["user_id", "partner_id"], ["users.id", "users.partner_id"],
            ondelete="CASCADE", name="fk_invitations_user_id_partner"),
        # Status enum + correlated timestamp (0010).
        CheckConstraint(
            "status IN ('pending', 'accepted', 'revoked', 'expired')",
            name="ck_invitations_status_enum"),
        CheckConstraint(
            "(status = 'accepted') = (accepted_at IS NOT NULL)",
            name="ck_invitation_accepted_at"),
        CheckConstraint(
            "(status <> 'pending') OR (accepted_at IS NULL)",
            name="ck_invitation_pending_no_accept"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
