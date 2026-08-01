"""Partner activity log: append events, and read them back with keyset
pagination + date/event filters.

Reads run under the caller's partner RLS scope, so the log is automatically
confined to that partner. Pagination is keyset on (created_at, id) DESC, which
rides the (partner_id, created_at DESC) index from migration 0002 and stays
stable while new events are being appended.
"""
import base64
import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

MAX_LIMIT = 200


def record(db: OrmSession, partner_id: UUID, event_type: str,
           actor_user_id: UUID | None = None, payload: dict | None = None) -> None:
    """Append one event. Path-agnostic raw insert (partner path re-checks
    partner_id via RLS WITH CHECK)."""
    db.execute(text(
        "INSERT INTO partner_activity_log (partner_id, actor_user_id, event_type, payload) "
        "VALUES (:p, :a, :e, cast(:pl AS jsonb))"),
        {"p": str(partner_id),
         "a": str(actor_user_id) if actor_user_id else None,
         "e": event_type,
         "pl": json.dumps(payload or {})})


def _encode_cursor(created_at: datetime, row_id: UUID) -> str:
    return base64.urlsafe_b64encode(f"{created_at.isoformat()}|{row_id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts_s, id_s = raw.rsplit("|", 1)
    return datetime.fromisoformat(ts_s), id_s


def query(db: OrmSession, *, event_type: str | None = None,
          start: datetime | None = None, end: datetime | None = None,
          limit: int = 50, cursor: str | None = None) -> tuple[list, str | None]:
    """Return (rows, next_cursor). rows are newest-first; next_cursor is None on
    the last page."""
    limit = max(1, min(limit, MAX_LIMIT))
    where: list[str] = []
    params: dict = {}
    if event_type:
        where.append("event_type = :etype")
        params["etype"] = event_type
    if start is not None:
        where.append("created_at >= :start")
        params["start"] = start
    if end is not None:
        where.append("created_at <= :end")
        params["end"] = end
    if cursor:
        c_ts, c_id = _decode_cursor(cursor)
        where.append("(created_at, id) < (:c_ts, cast(:c_id AS uuid))")
        params["c_ts"] = c_ts
        params["c_id"] = c_id

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    params["lim"] = limit + 1  # fetch one extra to detect a next page
    rows = db.execute(text(
        "SELECT id, event_type, actor_user_id, payload, created_at "
        f"FROM partner_activity_log{clause} "
        "ORDER BY created_at DESC, id DESC LIMIT :lim"), params).all()

    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(last.created_at, last.id)
    return rows, next_cursor
