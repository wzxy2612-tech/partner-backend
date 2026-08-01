"""Monthly token usage: accumulation, per-period separation, tenant isolation."""
from datetime import datetime, timezone

from sqlalchemy import text

from app.services import token_usage


def test_current_period_format():
    assert token_usage.current_period(datetime(2024, 3, 5, tzinfo=timezone.utc)) == "2024-03"


def test_usage_accumulates_within_period(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        token_usage.record_usage(db, ids.partner_a, 100, period="2024-03")
        token_usage.record_usage(db, ids.partner_a, 50, period="2024-03")
        token_usage.record_usage(db, ids.partner_a, 999, period="2024-04")
        assert token_usage.monthly_usage(db, "2024-03") == 150
        assert token_usage.monthly_usage(db, "2024-04") == 999


def test_usage_is_tenant_isolated(ids, platform_engine, partner_orm):
    with platform_engine.begin() as c:  # commit usage for partner B
        c.execute(text(
            "INSERT INTO token_usage (partner_id, period, tokens) VALUES (:p, '2024-05', 777)"),
            {"p": str(ids.partner_b)})
    with partner_orm(ids.partner_a) as db:
        assert token_usage.monthly_usage(db, "2024-05") == 0  # RLS hides B's usage
