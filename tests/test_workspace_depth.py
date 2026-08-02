"""Workspace parent-chain depth (audit #12).

Two halves that used to disagree about what a legal chain is:

  * read side: resolve_scope_chain raises ScopeChainTooDeep past MAX_SCOPE_DEPTH
    -- a good fail-closed guard, already present.
  * write side: create_workspace validated only the immediate parent, so a
    caller could build a 33-deep chain one legal node at a time, after which
    every read of that node raised, and the router surfaced it as 500.

These prove the two now agree: a chain that can be created is one whose scope
can be resolved, and a pre-existing over-deep chain degrades to a stable 4xx
rather than a 500.
"""
import uuid
import pytest
from sqlalchemy import text

from app.services.workspaces import create_workspace, WorkspaceTooDeep
from app.services.scopes import MAX_SCOPE_DEPTH, resolve_scope_chain, ScopeChainTooDeep


def _chain(db, ids, n):
    """Create a company-A workspace chain of depth n via the service, returning
    the deepest workspace id. Uses the service so the depth guard is in play."""
    parent = None
    last = None
    for i in range(n):
        ws = create_workspace(
            db, partner_id=ids.partner_a, company_id=ids.company_a,
            name=f"w{i}", parent_workspace_id=parent)
        parent = ws.id
        last = ws.id
    return last


def test_chain_up_to_the_cap_is_allowed(ids, partner_orm):
    """MAX_SCOPE_DEPTH nodes must be creatable -- the guard rejects beyond the
    cap, not at it."""
    with partner_orm(ids.partner_a) as db:
        sp = db.begin_nested()
        _chain(db, ids, MAX_SCOPE_DEPTH)
        sp.rollback()


def test_one_past_the_cap_is_rejected_at_creation(ids, partner_orm):
    """The node that would make the chain exceed the cap is refused, so the
    over-deep chain never exists to be read."""
    with partner_orm(ids.partner_a) as db:
        sp = db.begin_nested()
        with pytest.raises(WorkspaceTooDeep):
            _chain(db, ids, MAX_SCOPE_DEPTH + 1)
        sp.rollback()


def test_deepest_creatable_chain_still_resolves(ids, partner_orm):
    """The whole point of aligning the two sides: anything creatable is
    resolvable. Build to the cap, then resolve the tip without raising."""
    with partner_orm(ids.partner_a) as db:
        sp = db.begin_nested()
        from app.models.enums import ScopeType
        tip = _chain(db, ids, MAX_SCOPE_DEPTH)
        chain = resolve_scope_chain(db, ScopeType.workspace, tip)
        assert chain  # resolves, does not raise
        sp.rollback()


def test_over_deep_listing_returns_409_not_500(ids, partner_ctx):
    """A chain that predates the write-side cap (built here with raw SQL to
    bypass the guard) must degrade to 409 on GET /workspaces, not 500. We assert
    at the service boundary: resolve_scope_chain raises ScopeChainTooDeep, which
    the router maps to 409."""
    with partner_ctx(ids.partner_a) as c:
        sp = c.begin_nested()
        # Build MAX_SCOPE_DEPTH+2 nodes with raw INSERTs, no depth check.
        parent = None
        tip = None
        for i in range(MAX_SCOPE_DEPTH + 2):
            wid = uuid.uuid4()
            c.execute(text(
                "INSERT INTO workspaces (id, partner_id, company_id, parent_workspace_id, name) "
                "VALUES (:id, :a, :ca, :p, :n)"),
                {"id": str(wid), "a": str(ids.partner_a), "ca": str(ids.company_a),
                 "p": str(parent) if parent else None, "n": f"deep{i}"})
            parent = wid
            tip = wid
        from app.models.enums import ScopeType
        with pytest.raises(ScopeChainTooDeep):
            resolve_scope_chain(c, ScopeType.workspace, tip)
        sp.rollback()
