"""Workflow-template cloning, gated by connector verification.

A template declares the connector kinds it needs; a clone is refused until every
one of those is present AND verified for the partner. The gate itself
(missing_connectors) is a pure function; cloning copies the template definition
into a new draft workflow in the target company.
"""
import json
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.services.connectors import verified_kinds


def missing_connectors(required: list[str], verified: set[str]) -> list[str]:
    """Required connector kinds that are not yet verified. Pure."""
    return [k for k in required if k not in verified]


@dataclass
class CloneResult:
    workflow_id: UUID | None = None
    missing_connectors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.workflow_id is not None


def clone_template(db: OrmSession, partner_id: UUID, template_id: UUID,
                   company_id: UUID, name: str) -> CloneResult:
    tmpl = db.execute(text(
        "SELECT definition, required_connectors FROM workflow_templates WHERE id = :t"),
        {"t": str(template_id)}).first()
    if tmpl is None:
        raise ValueError("template not found")  # RLS hides other partners' templates

    required = list(tmpl.required_connectors or [])
    missing = missing_connectors(required, verified_kinds(db))
    if missing:
        return CloneResult(workflow_id=None, missing_connectors=missing)  # nothing written

    wf_id = uuid4()
    db.execute(text(
        "INSERT INTO workflows (id, partner_id, company_id, template_id, name, definition, status) "
        "VALUES (:id, :p, :c, :t, :n, cast(:d AS jsonb), 'draft')"),
        {"id": str(wf_id), "p": str(partner_id), "c": str(company_id), "t": str(template_id),
         "n": name, "d": json.dumps(tmpl.definition or {})})
    return CloneResult(workflow_id=wf_id, missing_connectors=[])
