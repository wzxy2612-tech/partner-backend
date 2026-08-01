"""Monthly per-partner token usage. record_usage upserts into the current
period's counter; monthly_usage reads it back (RLS-scoped)."""
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def current_period(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m")


def record_usage(db: OrmSession, partner_id: UUID, tokens: int,
                 period: str | None = None) -> None:
    period = period or current_period()
    db.execute(text(
        "INSERT INTO token_usage (partner_id, period, tokens) VALUES (:p, :period, :t) "
        "ON CONFLICT (partner_id, period) "
        "DO UPDATE SET tokens = token_usage.tokens + EXCLUDED.tokens, updated_at = now()"),
        {"p": str(partner_id), "period": period, "t": tokens})


def monthly_usage(db: OrmSession, period: str | None = None) -> int:
    period = period or current_period()
    return db.execute(text(
        "SELECT coalesce(sum(tokens), 0) FROM token_usage WHERE period = :period"),
        {"period": period}).scalar_one()
