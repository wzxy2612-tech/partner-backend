from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.db import platform_session
from app.services import onboarding

router = APIRouter(prefix="/invitations", tags=["invitations"])


class AcceptBody(BaseModel):
    token: str
    password: str


@router.post("/accept")
def accept(body: AcceptBody) -> dict:
    # No auth: the invitee has no session. Lookup by token runs on the platform path.
    with platform_session() as db:
        ok = onboarding.accept_invitation(db, body.token, body.password)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired invitation")
    return {"status": "accepted"}
