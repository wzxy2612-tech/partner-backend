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
from app.services.activity import record
from app.models.partner import Partner
from app.models.enums import PartnerStatus

SUSPENSION_RETENTION = timedelta(days=60)  # JD: 60-day suspension retention

# The platform tenant (0009). It is a real partners row so that platform
# administrators and direct customers have something to FK to -- it is not a
# customer, and the partner lifecycle does not apply to it.
NIL = UUID("00000000-0000-0000-0000-000000000000")


def suspend_partner(db: OrmSession, partner_id: UUID) -> int:
    """Suspend a partner, stamp the 60-day retention window, and revoke every
    live session across the partner. Returns the number of sessions revoked."""
    if partner_id == NIL:
        raise ValueError("the platform tenant cannot be suspended")
    now = datetime.now(timezone.utc)
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.suspended
    partner.suspended_at = now
    partner.suspension_retention_until = now + SUSPENSION_RETENTION
    db.flush()  # persist the state change within the transaction
    revoked = revoke_partner_sessions(db, partner_id)
    record(db, partner_id, "partner.suspended", payload={"sessions_revoked": revoked})
    return revoked


def activate_partner(db: OrmSession, partner_id: UUID) -> None:
    """Reactivate a partner and clear the suspension window."""
    if partner_id == NIL:
        raise ValueError("the platform tenant has no lifecycle to activate")
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.active
    partner.suspended_at = None
    partner.suspension_retention_until = None
    db.flush()
    record(db, partner_id, "partner.activated")


def deactivate_domain(db: OrmSession, partner_id: UUID, domain: str) -> int:
    """Deactivate all of a partner's users on an email domain and revoke their
    sessions. Scoped to one partner by the explicit partner_id predicate.
    Returns the number of users deactivated."""
    # Exact comparison on the parsed domain, not a LIKE pattern. The domain was
    # interpolated into `LIKE '%@' || domain`, so a caller passing '%' produced
    # '%@%' and deactivated every active user in the partner. Escaping the
    # wildcards would work and would leave the next author responsible for
    # remembering to escape; splitting the address removes pattern semantics
    # from the query altogether, so there is nothing left to forget.
    rows = db.execute(
        text("SELECT id FROM users "
             "WHERE partner_id = :pid AND split_part(lower(email), '@', 2) = :domain "
             "AND is_active = true"),
        {"pid": str(partner_id), "domain": domain.lower().lstrip("@")},
    ).all()
    user_ids = [r.id for r in rows]
    for uid in user_ids:
        db.execute(text("UPDATE users SET is_active = false WHERE id = :id"), {"id": str(uid)})
        revoke_user_sessions(db, uid)
    return len(user_ids)


def get_billing_contact(db: OrmSession, partner_id: UUID) -> str | None:
    return db.execute(
        text("SELECT billing_contact_email FROM partners WHERE id = :p"),
        {"p": str(partner_id)}).scalar_one_or_none()


def set_billing_contact(db: OrmSession, partner_id: UUID, email: str | None) -> int:
    """Set the partner's billing contact. Under the partner RLS scope, the
    partners policy (id = app.partner_id) means this can only touch the caller's
    own partner row -- a cross-tenant attempt updates 0 rows."""
    n = db.execute(
        text("UPDATE partners SET billing_contact_email = :e WHERE id = :p"),
        {"e": email, "p": str(partner_id)}).rowcount
    if n:
        record(db, partner_id, "partner.billing_contact_updated", payload={"email": email})
    return n
