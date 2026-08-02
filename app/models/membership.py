import uuid
from datetime import datetime

from sqlalchemy import (DateTime, ForeignKey, ForeignKeyConstraint,
                        CheckConstraint, Enum as SAEnum, Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import Role, ScopeType

NIL = "00000000-0000-0000-0000-000000000000"


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        Index("ix_memberships_partner_id", "partner_id"),
        UniqueConstraint("user_id", "scope_type", "scope_id", "role", name="uq_membership"),
        # Composite tenant FK to users (0007); partner_id keeps its own FK to
        # partners (0002).
        ForeignKeyConstraint(
            ["user_id", "partner_id"], ["users.id", "users.partner_id"],
            ondelete="CASCADE", name="fk_memberships_user_id_partner"),
        # Platform-role tuple (0010): the platform role and the platform tuple
        # imply each other, so a partner-scoped platform_super_admin (the
        # escalation) cannot exist.
        CheckConstraint(
            f"(role <> 'platform_super_admin' "
            f"  OR (partner_id = '{NIL}'::uuid AND scope_type = 'platform' "
            f"      AND scope_id = '{NIL}'::uuid)) "
            f"AND (scope_type <> 'platform' OR role = 'platform_super_admin')",
            name="ck_membership_platform_tuple"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[ScopeType] = mapped_column(
        SAEnum(ScopeType, name="scope_type", create_type=False), nullable=False)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    role: Mapped[Role] = mapped_column(SAEnum(Role, name="app_role", create_type=False), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
