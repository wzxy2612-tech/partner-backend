import uuid
from datetime import datetime

from sqlalchemy import (String, DateTime, ForeignKey, ForeignKeyConstraint,
                        CheckConstraint, Index, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Connector(Base):
    """A partner's integration (e.g. slack, gmail). Must be 'verified' before a
    workflow that requires it can be cloned/activated."""
    __tablename__ = "connectors"
    __table_args__ = (
        Index("ix_connectors_partner_id", "partner_id"),
        UniqueConstraint("partner_id", "kind", name="uq_connector_partner_kind"),
        CheckConstraint("status IN ('unverified', 'verified')",
                        name="ck_connectors_status_enum"),
        CheckConstraint("(status = 'verified') = (verified_at IS NOT NULL)",
                        name="ck_connector_verified_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unverified")
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class WorkflowTemplate(Base):
    """A parent-hub workflow template. ``required_connectors`` is a JSON list of
    connector kinds that must be verified before it can be cloned."""
    __tablename__ = "workflow_templates"
    __table_args__ = (
        Index("ix_workflow_templates_partner_id", "partner_id"),
        UniqueConstraint("id", "partner_id", name="uq_workflow_templates_id_partner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    definition: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    required_connectors: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Workflow(Base):
    """An instance cloned from a template into a company."""
    __tablename__ = "workflows"
    __table_args__ = (
        Index("ix_workflows_partner_id", "partner_id"),
        Index("ix_workflows_company_id", "company_id"),
        ForeignKeyConstraint(
            ["partner_id"], ["partners.id"], ondelete="CASCADE",
            name="fk_workflows_partner_id"),
        ForeignKeyConstraint(
            ["company_id", "partner_id"], ["companies.id", "companies.partner_id"],
            ondelete="CASCADE", name="fk_workflows_company_id_partner"),
        ForeignKeyConstraint(
            ["template_id", "partner_id"],
            ["workflow_templates.id", "workflow_templates.partner_id"],
            ondelete="SET NULL (template_id)",
            name="fk_workflows_template_id_partner"),
        CheckConstraint("status IN ('draft', 'active', 'archived')",
                        name="ck_workflows_status_enum"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    partner_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    company_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    template_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    definition: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
