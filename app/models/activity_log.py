import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, ForeignKey, ForeignKeyConstraint,
                        Index, func, text)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PartnerActivityLog(Base):
    __tablename__ = "partner_activity_log"
    __table_args__ = (
        Index("ix_activity_partner_created",
              "partner_id", text("created_at DESC")),
        Index("ix_activity_partner_event_created",
              "partner_id", "event_type", text("created_at DESC")),
        ForeignKeyConstraint(
            ["actor_user_id", "partner_id"], ["users.id", "users.partner_id"],
            ondelete="SET NULL (actor_user_id)",
            name="fk_partner_activity_log_actor_user_id_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
