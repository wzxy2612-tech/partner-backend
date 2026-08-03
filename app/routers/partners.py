from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.deps import require_platform, require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.db import platform_session
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services.partners import (suspend_partner, activate_partner, deactivate_domain,
                                   get_billing_contact, set_billing_contact)

router = APIRouter(prefix="/partners", tags=["partners"])


def _lifecycle_400(exc: ValueError) -> HTTPException:
    """The lifecycle guards raise ValueError; unmapped, they surface as 500.

    A 500 tells the caller the server broke when in fact the server refused,
    and the platform-tenant guards added in 0009 and 0015 are refusals. Kept as
    one flat 400 rather than guessing between 404 and 409: separating "no such
    partner" from "not a partner you may do this to" needs typed exceptions,
    and inventing that distinction from the message string is the error-text
    matching this codebase avoids everywhere else.
    """
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


class DomainBody(BaseModel):
    domain: str


class BillingContactBody(BaseModel):
    email: str | None = None


@router.post("/{partner_id}/suspend")
def suspend(partner_id: UUID, _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        try:
            revoked = suspend_partner(db, partner_id)
        except ValueError as exc:
            raise _lifecycle_400(exc)
    return {"partner_id": str(partner_id), "status": "suspended", "sessions_revoked": revoked}


@router.post("/{partner_id}/activate")
def activate(partner_id: UUID, _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        try:
            activate_partner(db, partner_id)
        except ValueError as exc:
            raise _lifecycle_400(exc)
    return {"partner_id": str(partner_id), "status": "active"}


@router.post("/{partner_id}/deactivate-domain")
def deactivate(partner_id: UUID, body: DomainBody,
               _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        try:
            count = deactivate_domain(db, partner_id, body.domain)
        except ValueError as exc:
            raise _lifecycle_400(exc)
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
        # 0 rows means the database refused -- the partner is not active. Saying
        # 200 here would report a write that did not happen, which is how the
        # stale-request window stayed invisible for two audit rounds.
        if not set_billing_contact(db, body.email):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "partner is not active")
    return {"partner_id": str(principal.partner_id), "billing_contact_email": body.email}
