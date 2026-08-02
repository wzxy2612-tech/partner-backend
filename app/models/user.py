import uuid
from datetime import datetime

from sqlalchemy import (String, Boolean, DateTime, ForeignKeyConstraint,
                        Index, UniqueConstraint, Enum as SAEnum, func, text)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import BillingSource


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_partner_id", "partner_id"),
        # Parent-side (id, partner_id) unique: every tenant-composite FK that
        # points at a user targets this (0007).
        UniqueConstraint("id", "partner_id", name="uq_users_id_partner"),
        # partner_id references partners since 0009 (the nil sentinel is a real
        # row now); RESTRICT so deleting a partner with users still fails loudly.
        ForeignKeyConstraint(["partner_id"], ["partners.id"],
                             ondelete="RESTRICT", name="fk_users_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # --- added by the partner multi-tenancy migration ---
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, default=uuid.UUID(int=0))  # nil = platform/direct
    billing_source: Mapped[BillingSource] = mapped_column(
        SAEnum(BillingSource, name="billing_source", create_type=False),
        nullable=False, default=BillingSource.stripe)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
