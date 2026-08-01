"""Activity log: keyset pagination, date/event filters, tenant isolation."""
from datetime import datetime, timezone

from sqlalchemy import text

from app.services import activity


def _seed(platform_engine, partner_id, specs):
    """specs: list of (event_type, created_at_iso). Seeded as platform (bypass)."""
    with platform_engine.begin() as c:
        for event_type, ts in specs:
            c.execute(text(
                "INSERT INTO partner_activity_log (partner_id, event_type, created_at) "
                "VALUES (:p, :e, :t)"),
                {"p": str(partner_id), "e": event_type, "t": ts})


THREE = [
    ("test.evt", "2024-01-01T00:00:00+00:00"),
    ("test.evt", "2024-01-02T00:00:00+00:00"),
    ("test.evt", "2024-01-03T00:00:00+00:00"),
]


def test_query_is_newest_first_with_event_filter(ids, platform_engine, partner_orm):
    _seed(platform_engine, ids.partner_a, [
        ("test.login", "2024-01-01T00:00:00+00:00"),
        ("test.logout", "2024-01-02T00:00:00+00:00"),
        ("test.login", "2024-01-03T00:00:00+00:00"),
    ])
    with partner_orm(ids.partner_a) as db:
        rows, nxt = activity.query(db, event_type="test.login", limit=50)
    assert [r.event_type for r in rows] == ["test.login", "test.login"]
    assert rows[0].created_at > rows[1].created_at  # newest first
    assert nxt is None


def test_date_range_filter(ids, platform_engine, partner_orm):
    _seed(platform_engine, ids.partner_a, THREE)
    with partner_orm(ids.partner_a) as db:
        rows, _ = activity.query(
            db,
            start=datetime(2024, 1, 2, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, 23, 59, tzinfo=timezone.utc))
    assert len(rows) == 1
    assert rows[0].created_at.date().isoformat() == "2024-01-02"


def test_keyset_pagination_no_overlap(ids, platform_engine, partner_orm):
    _seed(platform_engine, ids.partner_a, THREE)
    with partner_orm(ids.partner_a) as db:
        page1, cur1 = activity.query(db, event_type="test.evt", limit=2)
        assert len(page1) == 2 and cur1 is not None
        page2, cur2 = activity.query(db, event_type="test.evt", limit=2, cursor=cur1)
    assert len(page2) == 1 and cur2 is None
    assert {r.id for r in page1}.isdisjoint({r.id for r in page2})  # disjoint pages


def test_activity_is_tenant_isolated(ids, platform_engine, partner_orm):
    _seed(platform_engine, ids.partner_b, [("test.secret", "2024-01-01T00:00:00+00:00")])
    with partner_orm(ids.partner_a) as db:
        rows, _ = activity.query(db, event_type="test.secret")
    assert rows == []  # partner A cannot see partner B's events
