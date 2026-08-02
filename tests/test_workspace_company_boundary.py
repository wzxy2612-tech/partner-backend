"""Workspace parent must stay inside one company (audit #11).

0007 stopped a parent in another PARTNER. Inside one partner it allowed a parent
in another COMPANY, and that was an authorization bypass rather than a cosmetic
gap:

    resolve_scope_chain walked parent_workspace_id upward and reassigned
    company_id every iteration, so the chain carried the ROOT ancestor's company
    instead of the target's. A Company A workspace hung under a Company A2
    parent authorised as A2 -- and pulled A2's branding into it.

Three layers, tested separately because they fail independently:

  * the schema (0012), which makes such a link unwritable;
  * scope resolution, which pins the company to the TARGET so a legacy row
    cannot mis-authorise;
  * branding resolution, same pin -- a wrong company here means another
    company's brand configuration rendering inside this workspace.

The runtime tests build their bad data with raw SQL under a temporarily dropped
constraint, because after 0012 the schema will not let them create it. That is
the point: the backstop exists for rows that predate the constraint.
"""
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.enums import ScopeType
from app.services.scopes import resolve_scope_chain, CrossCompanyParent
from app.services.workspaces import resolve_branding


# --- the schema refuses the link --------------------------------------------

def test_parent_in_another_company_is_refused(ids, platform_ctx):
    """The bypass, refused at the database. Runs on the platform path so RLS
    contributes nothing -- a pass isolates the FK as the thing doing the work."""
    with platform_ctx() as c:
        parent = c.execute(text(
            "SELECT id FROM workspaces WHERE company_id = :ca2 LIMIT 1"),
            {"ca2": str(ids.company_a2)}).scalar()
        if parent is None:
            parent = uuid.uuid4()
            sp = c.begin_nested()
            c.execute(text(
                "INSERT INTO workspaces (id, partner_id, company_id, name) "
                "VALUES (:w, :a, :ca2, 'A2 hub')"),
                {"w": str(parent), "a": str(ids.partner_a), "ca2": str(ids.company_a2)})
            sp2 = c.begin_nested()
            with pytest.raises(IntegrityError):
                c.execute(text(
                    "INSERT INTO workspaces (id, partner_id, company_id, "
                    "parent_workspace_id, name) VALUES (:w, :a, :ca, :p, 'child')"),
                    {"w": str(uuid.uuid4()), "a": str(ids.partner_a),
                     "ca": str(ids.company_a), "p": str(parent)})
            sp2.rollback()
            sp.rollback()
            return
        sp = c.begin_nested()
        with pytest.raises(IntegrityError):
            c.execute(text(
                "INSERT INTO workspaces (id, partner_id, company_id, "
                "parent_workspace_id, name) VALUES (:w, :a, :ca, :p, 'child')"),
                {"w": str(uuid.uuid4()), "a": str(ids.partner_a),
                 "ca": str(ids.company_a), "p": str(parent)})
        sp.rollback()


def test_parent_in_the_same_company_still_works(ids, platform_ctx):
    """Tightness. The constraint must forbid crossing companies, not forbid
    parents -- the whole parent-hub feature depends on this staying legal."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        parent = uuid.uuid4()
        c.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, name) "
            "VALUES (:w, :a, :ca, 'hub')"),
            {"w": str(parent), "a": str(ids.partner_a), "ca": str(ids.company_a)})
        c.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, "
            "parent_workspace_id, name) VALUES (:w, :a, :ca, :p, 'child')"),
            {"w": str(uuid.uuid4()), "a": str(ids.partner_a),
             "ca": str(ids.company_a), "p": str(parent)})
        sp.rollback()


def test_root_workspace_still_allowed(ids, platform_ctx):
    """MATCH SIMPLE: a NULL parent means no reference, so the three-column FK is
    not checked. Roots must keep working."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        c.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, "
            "parent_workspace_id, name) VALUES (:w, :a, :ca, NULL, 'root')"),
            {"w": str(uuid.uuid4()), "a": str(ids.partner_a), "ca": str(ids.company_a)})
        sp.rollback()


# --- resolution pins the company to the TARGET ------------------------------

from contextlib import contextmanager


@contextmanager
def _legacy_cross_company_chain(owner_engine, ids):
    """Build the cross-company parent link that 0012 forbids, so the runtime
    backstops can be tested against it.

    Runs as the OWNER, because dropping a constraint requires table ownership --
    app_platform has BYPASSRLS and full DML but is not the owner, which is
    correct: the application must never be able to remove its own constraints.
    My first attempt did this on the platform connection and got
    "must be owner of table workspaces", which is the schema telling the truth.

    Everything happens inside a transaction that is always rolled back, so the
    constraint is restored and no row survives. Yields (hub_a2, child_a).
    """
    conn = owner_engine.connect()
    trans = conn.begin()
    try:
        conn.execute(text(
            'ALTER TABLE workspaces DROP CONSTRAINT "fk_workspaces_parent_partner_company"'))
        # workspaces is FORCE ROW LEVEL SECURITY, so the OWNER is subject to the
        # policy too -- that is the whole point of FORCE. Without a tenant scope
        # the walk reads zero rows, breaks on the first iteration and never
        # reaches the cross-company check, so the test would pass vacuously as
        # "DID NOT RAISE" rather than proving anything.
        #
        # 0011 additionally gates the policy on the partner being active, so the
        # scope has to name an active partner -- partner_a is.
        conn.execute(text("SELECT set_config('app.partner_id', :p, true)"),
                     {"p": str(ids.partner_a)})
        hub_a2, child_a = uuid.uuid4(), uuid.uuid4()
        conn.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, name, branding) "
            "VALUES (:w, :a, :ca2, 'A2 hub', '{\"logo\": \"a2\"}'::jsonb)"),
            {"w": str(hub_a2), "a": str(ids.partner_a), "ca2": str(ids.company_a2)})
        conn.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, "
            "parent_workspace_id, name, branding) "
            "VALUES (:w, :a, :ca, :p, 'legacy child', '{}'::jsonb)"),
            {"w": str(child_a), "a": str(ids.partner_a),
             "ca": str(ids.company_a), "p": str(hub_a2)})
        yield conn, hub_a2, child_a
    finally:
        trans.rollback()
        conn.close()


def test_scope_chain_refuses_a_legacy_cross_company_chain(ids, owner_engine):
    """The bypass itself. With a legacy cross-company link present, resolution
    must NOT quietly report the root's company -- that is what let a Company A2
    admin through on a Company A workspace. Fail closed instead."""
    with _legacy_cross_company_chain(owner_engine, ids) as (conn, _hub, child_a):
        with pytest.raises(CrossCompanyParent):
            resolve_scope_chain(conn, ScopeType.workspace, child_a)


def test_branding_does_not_inherit_another_companys_brand(ids, owner_engine):
    """The leak, which is sharper than the permission gap. A cross-company chain
    used to pull the ROOT company's branding into this workspace -- another
    company's brand configuration rendering here. The A2 hub carries a
    distinctive logo precisely so a silent inheritance would be visible."""
    with _legacy_cross_company_chain(owner_engine, ids) as (conn, _hub, child_a):
        with pytest.raises(CrossCompanyParent):
            resolve_branding(conn, child_a)


def test_same_company_chain_resolves_normally(ids, platform_ctx):
    """Tightness for the runtime pin: a legitimate same-company hub chain must
    resolve, and must name that company."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        hub, child = uuid.uuid4(), uuid.uuid4()
        c.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, name) "
            "VALUES (:w, :a, :ca, 'hub')"),
            {"w": str(hub), "a": str(ids.partner_a), "ca": str(ids.company_a)})
        c.execute(text(
            "INSERT INTO workspaces (id, partner_id, company_id, "
            "parent_workspace_id, name) VALUES (:w, :a, :ca, :p, 'child')"),
            {"w": str(child), "a": str(ids.partner_a),
             "ca": str(ids.company_a), "p": str(hub)})

        chain = resolve_scope_chain(c, ScopeType.workspace, child)
        assert (ScopeType.company, ids.company_a) in chain
        assert (ScopeType.company, ids.company_a2) not in chain
        sp.rollback()
