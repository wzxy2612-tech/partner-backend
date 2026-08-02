"""Workspace creation / listing under a partner's RLS scope.

Every write carries the caller's partner_id, which RLS independently checks
(WITH CHECK) -- so even a bug that passed the wrong partner_id would be refused
by the database rather than silently crossing tenants.
"""
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.workspace import Workspace
from app.services.scopes import (MAX_SCOPE_DEPTH, ScopeChainTooDeep,
                                 CrossCompanyParent)


class WorkspaceTooDeep(ValueError):
    """Creating this workspace would exceed MAX_SCOPE_DEPTH."""


def create_workspace(db: OrmSession, *, partner_id: UUID, company_id: UUID,
                     name: str, parent_workspace_id: UUID | None = None,
                     branding: dict | None = None) -> Workspace:
    """Create a workspace, validating the parent it is being hung under.

    Only company_id used to be authorized; parent_workspace_id was written
    straight through. Because scope resolution walks UP from a workspace and
    overwrites company_id with each ancestor's, hanging a Company A workspace
    under a Company A2 parent made it authorize -- and inherit branding -- as
    Company A2. A Company A2 admin could reach a workspace that belongs to
    Company A.

    NOTE (product decision, not a schema fact): this requires the parent to be
    in the SAME company. If a parent hub is ever meant to be shared across
    sibling companies, relax this check -- but then scope resolution must stop
    overwriting company_id on the way up, or the same escalation returns.
    Crossing PARTNERS is refused by the composite FK in 0007 regardless.
    """
    if parent_workspace_id is not None:
        parent = db.execute(text(
            "SELECT partner_id, company_id FROM workspaces WHERE id = :id"),
            {"id": str(parent_workspace_id)}).first()
        # RLS already hides other partners' rows, so None here means "absent, or
        # not yours". Both are refused identically and without distinguishing.
        if parent is None:
            raise ValueError("parent workspace not found")
        if parent.partner_id != partner_id:
            raise ValueError("parent workspace belongs to another partner")
        if parent.company_id != company_id:
            raise ValueError("parent workspace belongs to another company")

        # Reject before creating a node whose own chain would exceed the cap.
        # Walking the parent's ancestry here uses the same MAX_SCOPE_DEPTH the
        # read path enforces, so the two cannot disagree about what is legal: a
        # workspace that can be created is always one whose scope can be
        # resolved. Counting the parent's depth and requiring room for the child
        # means the deepest creatable chain is exactly MAX_SCOPE_DEPTH.
        depth = 1  # the child being created
        cur: UUID | None = parent_workspace_id
        seen: set[UUID] = set()
        while cur is not None:
            if cur in seen:
                raise ValueError("parent workspace chain contains a cycle")
            seen.add(cur)
            depth += 1
            if depth > MAX_SCOPE_DEPTH:
                raise WorkspaceTooDeep(
                    f"parent chain would exceed MAX_SCOPE_DEPTH ({MAX_SCOPE_DEPTH})")
            row = db.execute(text(
                "SELECT parent_workspace_id FROM workspaces WHERE id = :id"),
                {"id": str(cur)}).first()
            cur = row.parent_workspace_id if row else None

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
    # Pinned from the TARGET workspace, exactly as in resolve_scope_chain, and
    # for a sharper reason here: company_id used to be reassigned on every
    # iteration, so a chain crossing into another company pulled THAT company's
    # branding into this workspace. Not merely a permission bug -- another
    # tenant-adjacent company's brand configuration rendering inside your
    # workspace is a quiet data leak.
    #
    # A cross-company parent is not an inheritance mechanism, it is invalid
    # data. 0012 makes it unwritable; this is the runtime backstop for rows that
    # predate it.
    target_company_id: UUID | None = None
    seen: set[UUID] = set()
    while current is not None:
        # Same cap as the authorization walk: branding resolution follows the
        # identical parent chain and would hang on the identical cycle.
        if current in seen or len(seen) >= MAX_SCOPE_DEPTH:
            raise ScopeChainTooDeep(
                f"workspace parent chain from {workspace_id} cycles or exceeds "
                f"{MAX_SCOPE_DEPTH}")
        seen.add(current)
        row = db.execute(
            text("SELECT parent_workspace_id, company_id, branding "
                 "FROM workspaces WHERE id = :id"),
            {"id": str(current)},
        ).first()
        if row is None:
            break
        if target_company_id is None:
            target_company_id = row.company_id          # first row only
        elif row.company_id != target_company_id:
            raise CrossCompanyParent(
                f"workspace {current} is in company {row.company_id} but the "
                f"branding chain from {workspace_id} started in "
                f"{target_company_id}")
        layers.append(row.branding or {})
        current = row.parent_workspace_id

    # The company layer is the TARGET's company, never the chain's endpoint.
    if target_company_id is not None:
        crow = db.execute(
            text("SELECT branding FROM companies WHERE id = :id"),
            {"id": str(target_company_id)},
        ).first()
        if crow is not None:
            layers.append(crow.branding or {})

    # Company is the least specific; workspace itself the most. Apply far -> near.
    for layer in reversed(layers):
        merged.update(layer)
    return merged
