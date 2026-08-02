from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.db import platform_session
from app.services import onboarding

router = APIRouter(prefix="/invitations", tags=["invitations"])


class AcceptBody(BaseModel):
    # PBKDF2 produces a valid hash for the empty string, so "no policy" meant an
    # invitation could be redeemed with an empty password. A floor here is the
    # minimum; production would add breach-list and rate-limit checks too.
    token: str
    password: str = Field(min_length=12, max_length=1024)


@router.post("/accept")
def accept(body: AcceptBody) -> dict:
    # No auth: the invitee has no session. Lookup by token runs on the platform path.
    with platform_session() as db:
        ok = onboarding.accept_invitation(db, body.token, body.password)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired invitation")
    return {"status": "accepted"}
