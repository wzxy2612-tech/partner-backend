from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal
from app.auth.principal import Principal
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
        ws = create_workspace(
            db, partner_id=principal.partner_id, company_id=body.company_id,
            name=body.name, parent_workspace_id=body.parent_workspace_id,
            branding=body.branding)
        out = WorkspaceOut(id=ws.id, company_id=ws.company_id, name=ws.name,
                           parent_workspace_id=ws.parent_workspace_id)
    return out


@router.get("", response_model=list[WorkspaceOut])
def index(principal: Principal = Depends(require_partner)) -> list[WorkspaceOut]:
    with session_for_principal(principal) as db:
        rows = list_workspaces(db)
        return [WorkspaceOut(id=w.id, company_id=w.company_id, name=w.name,
                             parent_workspace_id=w.parent_workspace_id) for w in rows]
