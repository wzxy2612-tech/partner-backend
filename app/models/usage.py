import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, BigInteger, ForeignKey,
                        ForeignKeyConstraint, CheckConstraint, Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class TokenUsage(Base):
    """Monthly per-partner token counter (one row per partner per 'YYYY-MM')."""
    __tablename__ = "token_usage"
    __table_args__ = (
        Index("ix_token_usage_partner_id", "partner_id"),
        UniqueConstraint("partner_id", "period", name="uq_usage_partner_period"),
        # Value constraints from 0008: append-only non-negative counter, real
        # YYYY-MM period. Mirrored here so alembic check does not plan to drop
        # them.
        CheckConstraint("tokens >= 0", name="ck_token_usage_tokens_nonneg"),
        CheckConstraint(r"period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'",
                        name="ck_token_usage_period_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    period: Mapped[str] = mapped_column(String(7), nullable=False)
    tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Thread(Base):
    """A chat thread. Archived (archived_at stamped) once older than the retention
    window by the maintenance sweep."""
    __tablename__ = "threads"
    __table_args__ = (
        Index("ix_threads_partner_created", "partner_id", "created_at"),
        ForeignKeyConstraint(
            ["company_id", "partner_id"], ["companies.id", "companies.partner_id"],
            ondelete="CASCADE", name="fk_threads_company_id_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    company_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
