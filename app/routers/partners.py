from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_platform, require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.db import platform_session
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services.partners import (suspend_partner, activate_partner, deactivate_domain,
                                   get_billing_contact, set_billing_contact)

router = APIRouter(prefix="/partners", tags=["partners"])


class DomainBody(BaseModel):
    domain: str


class BillingContactBody(BaseModel):
    email: str | None = None


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


@router.get("/billing-contact")
def get_billing(principal: Principal = Depends(require_partner)) -> dict:
    # manage_billing at partner scope -> Partner Super Admin only.
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_billing, ScopeType.partner, principal.partner_id)
        email = get_billing_contact(db, principal.partner_id)
    return {"partner_id": str(principal.partner_id), "billing_contact_email": email}


@router.put("/billing-contact")
def put_billing(body: BillingContactBody,
                principal: Principal = Depends(require_partner)) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_billing, ScopeType.partner, principal.partner_id)
        set_billing_contact(db, principal.partner_id, body.email)
    return {"partner_id": str(principal.partner_id), "billing_contact_email": body.email}
