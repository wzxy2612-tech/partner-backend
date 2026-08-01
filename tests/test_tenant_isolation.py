"""Negative tests that prove cross-tenant access is impossible.

These are the point of the whole design: with RLS as the authority, a partner
connection cannot read, update, or insert another partner's rows, and a query
with no tenant context set returns nothing (fails closed).
"""
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def test_partner_sees_only_its_own_companies(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        names = conn.execute(text("SELECT name FROM companies ORDER BY name")).scalars().all()
    assert names == ["Company A", "Company A2"]  # both of partner A's companies


def test_cannot_read_another_partners_row_by_id(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        row = conn.execute(
            text("SELECT name FROM companies WHERE id = :cid"),
            {"cid": str(ids.company_b)}).first()
    assert row is None


def test_update_across_tenant_affects_zero_rows(ids, partner_ctx, platform_ctx):
    with partner_ctx(ids.partner_a) as conn:
        res = conn.execute(
            text("UPDATE companies SET name='HACKED' WHERE id = :cid"),
            {"cid": str(ids.company_b)})
        assert res.rowcount == 0
    with platform_ctx() as conn:  # confirm B untouched from the bypass view
        name = conn.execute(
            text("SELECT name FROM companies WHERE id = :cid"),
            {"cid": str(ids.company_b)}).scalar_one()
    assert name == "Company B"


def test_insert_for_foreign_partner_is_rejected(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        with pytest.raises(DBAPIError):  # WITH CHECK violation
            conn.execute(
                text("INSERT INTO companies (id, partner_id, name) VALUES (:id,:pid,'sneaky')"),
                {"id": str(uuid4()), "pid": str(ids.partner_b)})


def test_insert_for_own_partner_is_allowed(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        conn.execute(
            text("INSERT INTO companies (id, partner_id, name) VALUES (:id,:pid,'ok')"),
            {"id": str(uuid4()), "pid": str(ids.partner_a)})
        n = conn.execute(text("SELECT count(*) FROM companies WHERE name='ok'")).scalar_one()
    assert n == 1  # rolled back by the fixture afterwards


def test_missing_tenant_context_fails_closed(ids, partner_ctx):
    with partner_ctx(None) as conn:  # no set_config at all
        n = conn.execute(text("SELECT count(*) FROM companies")).scalar_one()
    assert n == 0


def test_partner_row_self_isolation(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        names = conn.execute(text("SELECT name FROM partners ORDER BY name")).scalars().all()
    assert names == ["Partner A"]


def test_activity_log_is_isolated(ids, partner_ctx):
    with partner_ctx(ids.partner_b) as conn:
        n = conn.execute(text("SELECT count(*) FROM partner_activity_log")).scalar_one()
    assert n == 1


def test_partner_cannot_see_direct_customer_users(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        emails = conn.execute(text("SELECT email FROM users ORDER BY email")).scalars().all()
    assert emails == ["a@partner.test", "ca@partner.test", "ro@partner.test"]  # partner A only


def test_platform_path_is_unchanged(ids, platform_ctx):
    """app_platform (BYPASSRLS) is the existing direct-customer / Stripe path:
    it still sees across all tenants and the direct customer is intact."""
    with platform_ctx() as conn:
        companies = conn.execute(text("SELECT count(*) FROM companies")).scalar_one()
        direct = conn.execute(
            text("SELECT email FROM users WHERE billing_source='stripe'")).scalars().all()
    assert companies == 3
    assert direct == ["direct@customer.test"]
