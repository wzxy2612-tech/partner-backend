"""FastAPI request dependencies that turn a bearer token into a Principal and
route each principal onto the correct DB path.

The tenant boundary is decided here, server-side, from the authenticated
session -- never from anything the client sends in the request body.
"""
from contextlib import contextmanager
from typing import Iterator

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session as OrmSession

from app.auth.principal import Principal, authenticate
from app.db import partner_session, platform_session
from app.models.enums import Role


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def get_principal(authorization: str | None = Header(default=None)) -> Principal:
    token = _bearer(authorization)
    # Auth resolution is a platform concern -- it precedes tenant scoping.
    with platform_session() as db:
        principal = authenticate(db, token)
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    # A suspended partner's users can authenticate but cannot act.
    if not principal.is_platform and principal.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "partner is suspended")
    return principal


def require_platform(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.is_platform or principal.has_role(Role.platform_super_admin):
        return principal
    raise HTTPException(status.HTTP_403_FORBIDDEN, "platform privileges required")


def require_partner(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.is_platform:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "a partner context is required")
    return principal


@contextmanager
def session_for_principal(principal: Principal) -> Iterator[OrmSession]:
    """Open the DB path that matches the principal: the RLS-scoped runtime path
    for a partner, the bypass path for platform/direct principals."""
    if principal.is_platform:
        with platform_session() as db:
            yield db
    else:
        with partner_session(principal.partner_id) as db:
            yield db
