from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.deps import require_partner, session_for_principal, enforce
from app.auth.principal import Principal
from app.models.enums import ScopeType
from app.services.rbac import Permission
from app.services import activity

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("")
def list_activity(
    principal: Principal = Depends(require_partner),
    event_type: str | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> dict:
    # view at PARTNER scope -> only a Partner Super Admin's grant reaches it.
    with session_for_principal(principal) as db:
        enforce(db, principal, Permission.view, ScopeType.partner, principal.partner_id)
        try:
            rows, next_cursor = activity.query(
                db, event_type=event_type, start=start, end=end, limit=limit, cursor=cursor)
        except activity.InvalidCursor as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
        items = [{
            "id": str(r.id),
            "event_type": r.event_type,
            "actor_user_id": str(r.actor_user_id) if r.actor_user_id else None,
            "payload": r.payload,
            "created_at": r.created_at.isoformat(),
        } for r in rows]
    return {"items": items, "next_cursor": next_cursor}
