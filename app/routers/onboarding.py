from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services import onboarding
from app.db import platform_session

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


class CsvBody(BaseModel):
    csv: str


def _resolve_taken(rows: list[dict]) -> set[str]:
    """Which of the submitted addresses already exist system-wide.

    Runs on the platform path because users.email is globally unique while the
    partner path can only see its own tenant -- without this, validate passes a
    row whose address belongs to another partner and the clash only appears as
    an IntegrityError mid-INSERT.

    Deliberately resolved BEFORE the partner transaction is opened: it is a
    read-only lookup on a different connection, and nesting it inside the
    business transaction would tie an unrelated session's lifetime (and commit)
    to the write path.

    Returns booleans only -- never which tenant holds an address."""
    emails = {(r.get("email") or "").lower()
              for r in rows if (r.get("email") or "").strip()}
    if not emails:
        return set()
    with platform_session() as pdb:
        return onboarding.taken_emails(pdb, emails)


@router.post("/validate")
def validate(body: CsvBody, principal: Principal = Depends(require_partner)) -> dict:
    """Step 1: dry run. Returns per-row errors and writes nothing."""
    rows = onboarding.parse_csv(body.csv)
    taken = _resolve_taken(rows)
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_users, ScopeType.partner, principal.partner_id)
        report = onboarding.validate(db, rows, taken)
    return report.as_dict()


@router.post("/commit")
def commit(body: CsvBody, principal: Principal = Depends(require_partner)) -> dict:
    """Step 2: validate again, then provision the whole batch in one transaction."""
    taken = _resolve_taken(onboarding.parse_csv(body.csv))
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.manage_users, ScopeType.partner, principal.partner_id)
        try:
            report, result = onboarding.onboard(
                db, principal.partner_id, body.csv, globally_taken=taken)
        except onboarding.EmailAlreadyRegistered as exc:
            # Lost the race between validate and INSERT. 409 rather than 500,
            # and the whole batch has already rolled back with it -- the caller
            # can re-run validate to get a fresh per-row report.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {"error": "email already registered", "email": exc.email})
        payload = report.as_dict()
        payload["provisioned"] = (
            [str(uid) for uid in result.created_user_ids] if result else [])
    return payload
