import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKeyConstraint, Index, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Session(Base):
    """Revocable server-side session. The DB row -- not the token body -- is the
    authority: revocation just stamps ``revoked_at``."""
    __tablename__ = "sessions"
    # Composite tenant FK (0007) + partner FK (0009). Declared to match the DDL
    # so `alembic check` stays clean; autogenerate would otherwise plan to
    # "restore" the single-column FK and weaken tenant isolation.
    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_partner_id", "partner_id"),
        ForeignKeyConstraint(
            ["user_id", "partner_id"], ["users.id", "users.partner_id"],
            ondelete="CASCADE", name="fk_sessions_user_id_partner"),
        ForeignKeyConstraint(
            ["partner_id"], ["partners.id"],
            ondelete="RESTRICT", name="fk_sessions_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, default=uuid.UUID(int=0))
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
