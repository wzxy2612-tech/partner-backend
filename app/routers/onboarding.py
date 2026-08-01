from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services.email import ConsoleEmailSender
from app.services import onboarding

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


class CsvBody(BaseModel):
    csv: str


@router.post("/validate")
def validate(body: CsvBody, principal: Principal = Depends(require_partner)) -> dict:
    """Step 1: dry run. Returns per-row errors and writes nothing."""
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_users, ScopeType.partner, principal.partner_id)
        report = onboarding.validate(db, onboarding.parse_csv(body.csv))
    return report.as_dict()


@router.post("/commit")
def commit(body: CsvBody, principal: Principal = Depends(require_partner)) -> dict:
    """Step 2: validate again, then provision the whole batch in one transaction."""
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_users, ScopeType.partner, principal.partner_id)
        report, result = onboarding.onboard(
            db, principal.partner_id, body.csv, sender=ConsoleEmailSender())
        payload = report.as_dict()
        payload["provisioned"] = (
            [str(uid) for uid in result.created_user_ids] if result else [])
    return payload
