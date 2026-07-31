"""Partner lifecycle: activation / suspension / domain deactivation.

Suspension and domain deactivation each pair a state change with token
revocation, done in the SAME transaction so a partner can never be left
suspended-but-still-logged-in. Suspension is a platform / parent-hub capability
and runs on the platform path.
"""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.auth.sessions import revoke_partner_sessions, revoke_user_sessions
from app.models.partner import Partner
from app.models.enums import PartnerStatus

SUSPENSION_RETENTION = timedelta(days=60)  # JD: 60-day suspension retention


def suspend_partner(db: OrmSession, partner_id: UUID) -> int:
    """Suspend a partner, stamp the 60-day retention window, and revoke every
    live session across the partner. Returns the number of sessions revoked."""
    now = datetime.now(timezone.utc)
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.suspended
    partner.suspended_at = now
    partner.suspension_retention_until = now + SUSPENSION_RETENTION
    db.flush()
    return revoke_partner_sessions(db, partner_id)


def activate_partner(db: OrmSession, partner_id: UUID) -> None:
    """Reactivate a partner and clear the suspension window."""
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.active
    partner.suspended_at = None
    partner.suspension_retention_until = None
    db.flush()


def deactivate_domain(db: OrmSession, partner_id: UUID, domain: str) -> int:
    """Deactivate all of a partner's users on an email domain and revoke their
    sessions. Scoped to one partner by the explicit partner_id predicate.
    Returns the number of users deactivated."""
    rows = db.execute(
        text("SELECT id FROM users "
             "WHERE partner_id = :pid AND lower(email) LIKE :pat AND is_active = true"),
        {"pid": str(partner_id), "pat": f"%@{domain.lower()}"},
    ).all()
    user_ids = [r.id for r in rows]
    for uid in user_ids:
        db.execute(text("UPDATE users SET is_active = false WHERE id = :id"), {"id": str(uid)})
        revoke_user_sessions(db, uid)
    return len(user_ids)
