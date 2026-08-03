from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from app.auth.principal import authenticate
from app.auth.password import verify_password
from app.auth.sessions import issue_session, revoke_token
from app.db import platform_session
from app.models.user import User
from app.auth.principal import NIL
from sqlalchemy import text

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str


@router.post("/login", response_model=TokenResponse)
def login(body: LoginBody) -> TokenResponse:
    with platform_session() as db:
        user = db.query(User).filter(User.email == body.email).one_or_none()
        if user is None or not user.is_active or not user.hashed_password \
                or not verify_password(body.password, user.hashed_password):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        # A suspended partner's users must not receive a NEW session.
        #
        # suspend_partner revokes the sessions that exist at the moment it runs,
        # but login only checked the user. So a user could log in DURING a
        # suspension, be blocked by the 403 in get_principal, and then have that
        # token silently become usable again the instant the partner was
        # reactivated -- a credential minted while suspended, surviving the
        # suspension. Refusing issuance means reactivation only admits sessions
        # created after it.
        #
        # Locked FOR SHARE: the read and the issuance are one atomic decision,
        # so a suspend committing concurrently either happens fully before this
        # (and we refuse) or waits until after (and revokes the token we just
        # issued). Without the lock the suspend can land between them and leave
        # a live session behind.
        if user.partner_id != NIL:
            # partner_is_active(), not an inline status comparison.
            #
            # This was `row.status != "active"` -- a second, independent copy of
            # a fact that twelve RLS policies already get from one function.
            # Two copies agree until the definition moves: add a
            # `pending_deletion` state, or a retention window that keeps a row
            # nominally active, and the policies and this line start answering
            # differently for the same partner. Nothing would fail loudly; login
            # would just admit sessions the database was refusing to serve.
            #
            # The FOR SHARE stays exactly where it was. It is what makes the
            # read and the issuance one decision.
            #
            # It is legal here only because login runs on the platform
            # connection: SELECT ... FOR SHARE requires UPDATE privilege on the
            # table, and app_runtime has held none on partners since 0015.
            # Moving this query to the runtime path would fail with permission
            # denied, not with a wrong answer.
            row = db.execute(text(
                "SELECT public.partner_is_active(id) AS active "
                "FROM partners WHERE id = :pid FOR SHARE"),
                {"pid": str(user.partner_id)}).first()
            if row is None or not row.active:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "partner is suspended")
        # Scope is taken from the stored user, not from the request.
        token = issue_session(db, user_id=user.id, partner_id=user.partner_id)
    return TokenResponse(token=token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(authorization: str | None = Header(default=None)) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() == "bearer" and token:
        with platform_session() as db:
            revoke_token(db, token)
