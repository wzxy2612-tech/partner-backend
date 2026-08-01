"""Parent-hub branding inheritance.

A workspace's effective branding is the company's base branding, overlaid by each
ancestor hub down to the workspace itself (nearer ancestors win). resolve_branding
(the walk) lives in the workspaces service; here we add the setters. Everything is
RLS-scoped to the caller's partner.
"""
import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.services.workspaces import resolve_branding  # re-exported for the router

__all__ = ["resolve_branding", "set_workspace_branding", "set_company_branding"]


def set_workspace_branding(db: OrmSession, workspace_id: UUID, branding: dict) -> int:
    return db.execute(
        text("UPDATE workspaces SET branding = cast(:b AS jsonb) WHERE id = :id"),
        {"b": json.dumps(branding), "id": str(workspace_id)}).rowcount


def set_company_branding(db: OrmSession, company_id: UUID, branding: dict) -> int:
    return db.execute(
        text("UPDATE companies SET branding = cast(:b AS jsonb) WHERE id = :id"),
        {"b": json.dumps(branding), "id": str(company_id)}).rowcount
