"""Workspace tree is under the same RLS regime as the other partner tables."""
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def test_partner_sees_only_its_workspaces(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        names = conn.execute(text("SELECT name FROM workspaces ORDER BY name")).scalars().all()
    assert names == ["Child A", "Hub A"]  # not "Hub B"


def test_cannot_read_foreign_workspace_by_id(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        row = conn.execute(text("SELECT name FROM workspaces WHERE id = :w"),
                           {"w": str(ids.workspace_b)}).first()
    assert row is None


def test_insert_workspace_for_foreign_partner_rejected(ids, partner_ctx):
    with partner_ctx(ids.partner_a) as conn:
        with pytest.raises(DBAPIError):  # WITH CHECK on partner_id
            conn.execute(
                text("INSERT INTO workspaces (id, partner_id, company_id, name) "
                     "VALUES (:id,:pid,:cid,'sneaky')"),
                {"id": str(uuid4()), "pid": str(ids.partner_b), "cid": str(ids.company_b)})


def test_missing_context_hides_all_workspaces(ids, partner_ctx):
    with partner_ctx(None) as conn:
        n = conn.execute(text("SELECT count(*) FROM workspaces")).scalar_one()
    assert n == 0
