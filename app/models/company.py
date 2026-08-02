import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, ForeignKey, Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Company(Base):
    __tablename__ = "companies"
    __table_args__ = (
        Index("ix_companies_partner_id", "partner_id"),
        UniqueConstraint("id", "partner_id", name="uq_companies_id_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    branding: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)  # parent-hub branding
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
