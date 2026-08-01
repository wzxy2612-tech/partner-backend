from fastapi import APIRouter, Depends, Query

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services import token_usage

router = APIRouter(tags=["usage"])


@router.get("/token-usage")
def get_usage(principal: Principal = Depends(require_partner),
              period: str | None = Query(default=None, description="YYYY-MM")) -> dict:
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.view, ScopeType.partner, principal.partner_id)
        period = period or token_usage.current_period()
        tokens = token_usage.monthly_usage(db, period)
    return {"partner_id": str(principal.partner_id), "period": period, "tokens": tokens}
