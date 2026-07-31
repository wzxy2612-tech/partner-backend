from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from app.auth.principal import authenticate
from app.auth.password import verify_password
from app.auth.sessions import issue_session, revoke_token
from app.db import platform_session
from app.models.user import User

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
        # Scope is taken from the stored user, not from the request.
        token = issue_session(db, user_id=user.id, partner_id=user.partner_id)
    return TokenResponse(token=token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(authorization: str | None = Header(default=None)) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() == "bearer" and token:
        with platform_session() as db:
            revoke_token(db, token)
