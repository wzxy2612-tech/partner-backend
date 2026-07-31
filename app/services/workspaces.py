"""Workspace creation / listing under a partner's RLS scope.

Every write carries the caller's partner_id, which RLS independently checks
(WITH CHECK) -- so even a bug that passed the wrong partner_id would be refused
by the database rather than silently crossing tenants.
"""
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.workspace import Workspace


def create_workspace(db: OrmSession, *, partner_id: UUID, company_id: UUID,
                     name: str, parent_workspace_id: UUID | None = None,
                     branding: dict | None = None) -> Workspace:
    ws = Workspace(
        partner_id=partner_id, company_id=company_id, name=name,
        parent_workspace_id=parent_workspace_id, branding=branding or {})
    db.add(ws)
    db.flush()
    return ws


def list_workspaces(db: OrmSession) -> list[Workspace]:
    # RLS already constrains this to the caller's partner; no WHERE needed.
    return db.query(Workspace).order_by(Workspace.created_at).all()


def resolve_branding(db: OrmSession, workspace_id: UUID) -> dict:
    """Effective branding for a workspace: walk up the parent-hub chain, then the
    company, merging so nearer ancestors win. Demonstrates parent-hub
    inheritance; the full branding API lands in Phase 4."""
    merged: dict = {}
    layers: list[dict] = []

    current: UUID | None = workspace_id
    company_id = None
    while current is not None:
        row = db.execute(
            text("SELECT parent_workspace_id, company_id, branding "
                 "FROM workspaces WHERE id = :id"),
            {"id": str(current)},
        ).first()
        if row is None:
            break
        layers.append(row.branding or {})
        company_id = row.company_id
        current = row.parent_workspace_id

    if company_id is not None:
        crow = db.execute(
            text("SELECT branding FROM companies WHERE id = :id"),
            {"id": str(company_id)},
        ).first()
        if crow is not None:
            layers.append(crow.branding or {})

    # Company is the least specific; workspace itself the most. Apply far -> near.
    for layer in reversed(layers):
        merged.update(layer)
    return merged
