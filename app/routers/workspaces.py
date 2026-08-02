from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal, enforce
from app.services.rbac import principal_can
from app.services.scopes import resolve_scope_chain
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services.workspaces import create_workspace, list_workspaces

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


class WorkspaceBody(BaseModel):
    company_id: UUID
    name: str
    parent_workspace_id: UUID | None = None
    branding: dict | None = None


class WorkspaceOut(BaseModel):
    id: UUID
    company_id: UUID
    name: str
    parent_workspace_id: UUID | None = None


@router.post("", response_model=WorkspaceOut)
def create(body: WorkspaceBody, principal: Principal = Depends(require_partner)) -> WorkspaceOut:
    # partner_id comes from the principal; RLS re-checks it on write.
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_workspaces, ScopeType.company, body.company_id)
        try:
            ws = create_workspace(
                db, partner_id=principal.partner_id, company_id=body.company_id,
                name=body.name, parent_workspace_id=body.parent_workspace_id,
                branding=body.branding)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        out = WorkspaceOut(id=ws.id, company_id=ws.company_id, name=ws.name,
                           parent_workspace_id=ws.parent_workspace_id)
    return out


@router.get("", response_model=list[WorkspaceOut])
def index(principal: Principal = Depends(require_partner)) -> list[WorkspaceOut]:
    """List the workspaces this principal may actually see.

    RLS bounds this to the caller's partner and stops there -- it knows nothing
    about companies or grants. So a Company A read-only user was enumerating
    every workspace in the partner, including Company B's names, ids and tree
    structure. Tenant isolation is not authorization; a listing endpoint needs
    both, and only one of them is free.

    Filtered per row rather than by a WHERE clause so that the visibility rule
    stays the same function that decides single-item access. A dedicated SQL
    predicate would be a second place where "can they see this" gets decided,
    and the two would drift.
    """
    with session_for_principal(principal) as db:
        rows = list_workspaces(db)
        visible = [
            w for w in rows
            if principal_can(principal.grants, Permission.view,
                             resolve_scope_chain(db, ScopeType.workspace, w.id))
        ]
        return [WorkspaceOut(id=w.id, company_id=w.company_id, name=w.name,
                             parent_workspace_id=w.parent_workspace_id) for w in visible]
