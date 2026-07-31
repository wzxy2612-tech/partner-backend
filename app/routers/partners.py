from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_platform
from app.auth.principal import Principal
from app.db import platform_session
from app.services.partners import suspend_partner, activate_partner, deactivate_domain

router = APIRouter(prefix="/partners", tags=["partners"])


class DomainBody(BaseModel):
    domain: str


@router.post("/{partner_id}/suspend")
def suspend(partner_id: UUID, _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        revoked = suspend_partner(db, partner_id)
    return {"partner_id": str(partner_id), "status": "suspended", "sessions_revoked": revoked}


@router.post("/{partner_id}/activate")
def activate(partner_id: UUID, _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        activate_partner(db, partner_id)
    return {"partner_id": str(partner_id), "status": "active"}


@router.post("/{partner_id}/deactivate-domain")
def deactivate(partner_id: UUID, body: DomainBody,
               _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        count = deactivate_domain(db, partner_id, body.domain)
    return {"partner_id": str(partner_id), "domain": body.domain, "users_deactivated": count}
