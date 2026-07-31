"""Session lifecycle on the platform path. Every function takes an explicit
Session so callers control the transaction -- e.g. suspending a partner and
revoking all its sessions happen atomically in one platform transaction.
"""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.auth.tokens import new_token, hash_token
from app.models.session import Session as SessionRow

DEFAULT_TTL = timedelta(hours=8)


def issue_session(db: OrmSession, *, user_id: UUID, partner_id: UUID,
                  ttl: timedelta = DEFAULT_TTL) -> str:
    """Create a session row and return the RAW token (shown to the client once)."""
    token = new_token()
    now = datetime.now(timezone.utc)
    db.add(SessionRow(
        user_id=user_id, partner_id=partner_id,
        token_hash=hash_token(token), expires_at=now + ttl))
    db.flush()
    return token


def revoke_token(db: OrmSession, token: str) -> int:
    """Revoke the single session identified by a presented token (logout)."""
    return db.execute(
        text("UPDATE sessions SET revoked_at = now() "
             "WHERE token_hash = :h AND revoked_at IS NULL"),
        {"h": hash_token(token)},
    ).rowcount


def revoke_user_sessions(db: OrmSession, user_id: UUID) -> int:
    """Revoke every live session for one user (domain deactivation, forced logout)."""
    return db.execute(
        text("UPDATE sessions SET revoked_at = now() "
             "WHERE user_id = :uid AND revoked_at IS NULL"),
        {"uid": str(user_id)},
    ).rowcount


def revoke_partner_sessions(db: OrmSession, partner_id: UUID) -> int:
    """Revoke every live session across a whole partner (suspension)."""
    return db.execute(
        text("UPDATE sessions SET revoked_at = now() "
             "WHERE partner_id = :pid AND revoked_at IS NULL"),
        {"pid": str(partner_id)},
    ).rowcount
