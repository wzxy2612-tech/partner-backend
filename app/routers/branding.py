from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services import branding

router = APIRouter(tags=["branding"])


class BrandingBody(BaseModel):
    branding: dict


@router.get("/workspaces/{workspace_id}/branding")
def get_workspace_branding(workspace_id: UUID,
                           principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.view, ScopeType.workspace, workspace_id)
        effective = branding.resolve_branding(db, workspace_id)
    return {"workspace_id": str(workspace_id), "effective": effective}


@router.put("/workspaces/{workspace_id}/branding")
def set_workspace_branding(workspace_id: UUID, body: BrandingBody,
                           principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_workspaces, ScopeType.workspace, workspace_id)
        updated = branding.set_workspace_branding(db, workspace_id, body.branding)
        effective = branding.resolve_branding(db, workspace_id)
    return {"updated": updated, "effective": effective}


@router.put("/companies/{company_id}/branding")
def set_company_branding(company_id: UUID, body: BrandingBody,
                         principal: Principal = Depends(require_partner)) -> dict:
    # base ("parent-hub") branding: manage_companies -> Partner Super Admin only.
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_companies, ScopeType.company, company_id)
        updated = branding.set_company_branding(db, company_id, body.branding)
    return {"updated": updated}
