"""Scheduled maintenance jobs (cron/worker). These run on the PLATFORM path
(BYPASSRLS): retention and archival are cross-tenant sweeps, not partner actions.
"""
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def purge_expired_suspensions(db: OrmSession) -> list[UUID]:
    """Hard-delete partners whose 60-day suspension retention window has passed.
    Deleting the partner cascades companies/workspaces/memberships/invitations/
    activity; deleting its users cascades their sessions. Returns purged ids."""
    rows = db.execute(text(
        "SELECT id FROM partners "
        "WHERE status = 'suspended' AND suspension_retention_until IS NOT NULL "
        "AND suspension_retention_until < now()")).all()
    purged: list[UUID] = []
    for (pid,) in rows:
        db.execute(text("DELETE FROM users WHERE partner_id = :p"), {"p": str(pid)})
        db.execute(text("DELETE FROM partners WHERE id = :p"), {"p": str(pid)})
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
