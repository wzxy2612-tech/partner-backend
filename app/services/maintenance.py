"""Scheduled maintenance jobs (cron/worker). These run on the PLATFORM path
(BYPASSRLS): retention and archival are cross-tenant sweeps, not partner actions.
"""
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def purge_expired_suspensions(db: OrmSession) -> list[UUID]:
    """Hard-delete partners whose 60-day suspension retention window has passed.
    Deleting the partner cascades companies/workspaces/memberships/invitations/
    activity; deleting its users cascades their sessions. Returns purged ids.

    The users delete below is load-bearing since 0009: users.partner_id is now
    ON DELETE RESTRICT, so the partner delete fails if any remain. That is the
    intended direction -- a future purge path that forgets this step gets an
    error, rather than CASCADE quietly removing accounts.

    The platform tenant can never appear here: it is never suspended (guarded in
    partners.suspend_partner) and a trigger refuses its deletion outright."""
    # Candidates are LOCKED, not merely read. The old shape selected expired
    # partners and then deleted each by id -- so a concurrent activate could
    # commit between the two, and the purge would delete a partner that was
    # live again. SKIP LOCKED lets a second concurrent purge take different
    # rows instead of blocking on ours.
    rows = db.execute(text(
        "SELECT id FROM partners "
        "WHERE status = 'suspended' AND suspension_retention_until IS NOT NULL "
        "AND suspension_retention_until < now() "
        "FOR UPDATE SKIP LOCKED")).all()

    purged: list[UUID] = []
    for (pid,) in rows:
        # Re-assert the predicate in the DELETE itself. The lock means an
        # activate cannot commit while we hold the row, but it may have
        # committed BEFORE we locked it -- in which case our snapshot is stale
        # and the conditional delete matches nothing. Only a row that comes back
        # from RETURNING was actually still purgeable at delete time, and only
        # then do we touch its users.
        #
        # Deleting users first is required (users.partner_id is ON DELETE
        # RESTRICT since 0009), so the order is: confirm-by-locking, delete
        # children, delete parent conditionally, and treat RETURNING as the
        # authority on whether it happened.
        still = db.execute(text(
            "SELECT id FROM partners WHERE id = :p AND status = 'suspended' "
            "AND suspension_retention_until IS NOT NULL "
            "AND suspension_retention_until < now()"), {"p": str(pid)}).first()
        if still is None:
            continue  # activated (or already purged) since our snapshot
        db.execute(text("DELETE FROM users WHERE partner_id = :p"), {"p": str(pid)})
        deleted = db.execute(text(
            "DELETE FROM partners WHERE id = :p AND status = 'suspended' "
            "AND suspension_retention_until IS NOT NULL "
            "AND suspension_retention_until < now() "
            "RETURNING id"), {"p": str(pid)}).first()
        if deleted is not None:
            purged.append(pid)
    return purged


def archive_expired_threads(db: OrmSession, older_than_days: int = 365) -> int:
    """Stamp archived_at on chat threads older than the retention window (default
    1 year). Returns the number archived."""
    return db.execute(text(
        "UPDATE threads SET archived_at = now() "
        "WHERE archived_at IS NULL "
        f"AND created_at < now() - make_interval(days => :d)"),
        {"d": older_than_days}).rowcount
