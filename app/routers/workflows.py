from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services import connectors, workflows

router = APIRouter(tags=["workflows"])


class ConnectorBody(BaseModel):
    kind: str
    config: dict | None = None


class CloneBody(BaseModel):
    template_id: UUID
    company_id: UUID
    name: str


@router.post("/connectors")
def register_connector(body: ConnectorBody,
                       principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_workspaces, ScopeType.partner, principal.partner_id)
        cid = connectors.register_connector(db, principal.partner_id, body.kind, body.config)
    return {"id": str(cid), "kind": body.kind, "status": "unverified"}


@router.post("/connectors/{kind}/verify")
def verify_connector(kind: str, principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_workspaces, ScopeType.partner, principal.partner_id)
        ok = connectors.verify_connector(db, principal.partner_id, kind)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connector not found")
    return {"kind": kind, "status": "verified"}


@router.post("/workflows/clone")
def clone_workflow(body: CloneBody, principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_workspaces, ScopeType.company, body.company_id)
        result = workflows.clone_template(
            db, principal.partner_id, body.template_id, body.company_id, body.name)
        if not result.ok:
            # connector verification gate: refuse and report what's missing
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"error": "connectors not verified",
                        "missing_connectors": result.missing_connectors})
        return {"workflow_id": str(result.workflow_id), "status": "draft"}
