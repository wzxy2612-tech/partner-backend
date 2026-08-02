from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.deps import require_platform
from app.auth.principal import Principal
from app.db import platform_session
from app.services import maintenance

router = APIRouter(prefix="/admin/maintenance", tags=["maintenance"])


class ArchiveBody(BaseModel):
    # Bounded on both ends. -1 meant "older than tomorrow", which archived
    # essentially every thread in the system; the endpoint runs cross-tenant on
    # the platform path, so the blast radius was everything.
    #
    # A caller-supplied retention window is itself the questionable part: in
    # production this should be a fixed policy, with the parameter kept only for
    # operator override. Bounding it is the floor, not the resolution.
    older_than_days: int = Field(default=365, ge=1, le=3650)


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
