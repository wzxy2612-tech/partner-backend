from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import require_platform
from app.auth.principal import Principal
from app.db import platform_session
from app.services import maintenance

router = APIRouter(prefix="/admin/maintenance", tags=["maintenance"])


class ArchiveBody(BaseModel):
    older_than_days: int = 365


@router.post("/purge-suspensions")
def purge_suspensions(_: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        purged = maintenance.purge_expired_suspensions(db)
    return {"purged_partner_ids": [str(p) for p in purged], "count": len(purged)}


@router.post("/archive-threads")
def archive_threads(body: ArchiveBody, _: Principal = Depends(require_platform)) -> dict:
    with platform_session() as db:
        n = maintenance.archive_expired_threads(db, body.older_than_days)
    return {"archived": n, "older_than_days": body.older_than_days}
