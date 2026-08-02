import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, ForeignKey, ForeignKeyConstraint,
                        Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Workspace(Base):
    """Company-scoped node in a parent/child tree. ``parent_workspace_id`` is the
    parent hub; branding with NULL/absent keys inherits up the chain."""
    __tablename__ = "workspaces"
    __table_args__ = (
        Index("ix_workspaces_partner_id", "partner_id"),
        Index("ix_workspaces_company_id", "company_id"),
        Index("ix_workspaces_parent_id", "parent_workspace_id"),
        # Parent-side (id, partner_id) unique so other tables' composite FKs can
        # target workspaces (0007).
        UniqueConstraint("id", "partner_id", name="uq_workspaces_id_partner"),
        # 0012: the key the three-column parent FK targets.
        UniqueConstraint("id", "partner_id", "company_id",
                         name="uq_workspaces_id_partner_company"),
        # partner_id FK to partners (0002).
        ForeignKeyConstraint(
            ["partner_id"], ["partners.id"], ondelete="CASCADE",
            name="fk_workspaces_partner_id"),
        # company_id carries partner_id: composite FK to companies (0007).
        ForeignKeyConstraint(
            ["company_id", "partner_id"], ["companies.id", "companies.partner_id"],
            ondelete="CASCADE", name="fk_workspaces_company_id_partner"),
        # Self-referential parent, also tenant-composite; SET NULL keeps a
        # child when its parent is removed (0007).
        # 0012 widened this to include company: a parent in another COMPANY
        # inside the same partner was an authorization bypass, because scope
        # resolution reported the chain root's company. Two columns were not
        # enough.
        ForeignKeyConstraint(
            ["parent_workspace_id", "partner_id", "company_id"],
            ["workspaces.id", "workspaces.partner_id", "workspaces.company_id"],
            ondelete="SET NULL (parent_workspace_id)",
            name="fk_workspaces_parent_partner_company"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    company_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    parent_workspace_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    branding: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
