"""Platform-role integrity and status-field constraints (audit #1, #6).

The #1 test is the escalation the audit reproduced, turned into an assertion:
under partner A's OWN runtime scope, inserting a platform_super_admin membership
must be refused by the database. It runs on partner_ctx (the real app_runtime
role, RLS active), because that is the exact position the attacker held -- not a
privileged connection. A pass means the row never lands, so the "log back in as
a platform admin" second step has nothing to build on.

The #6 tests pin the status columns' correlated invariants: a connector cannot
be 'verified' with a NULL verified_at, which verified_kinds() would otherwise
accept as usable.
"""
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, DataError


def _fails(conn, sql, **params):
    sp = conn.begin_nested()
    try:
        conn.execute(text(sql), params)
    except (IntegrityError, DataError):
        sp.rollback()
        return True
    sp.rollback()
    return False


# --- #1: the escalation, refused at the database ----------------------------

def test_runtime_cannot_write_partner_scoped_platform_admin(ids, partner_ctx):
    """The reproduction. app_runtime, inside partner A's scope, tries to grant
    itself platform_super_admin anchored to its own (partner) tenant. The
    platform-tuple CHECK refuses it."""
    with partner_ctx(ids.partner_a) as c:
        assert _fails(c,
            "INSERT INTO memberships (user_id, partner_id, scope_type, scope_id, role) "
            "VALUES (:u, :a, 'partner', :a, 'platform_super_admin')",
            u=str(ids.user_a), a=str(ids.partner_a))


def test_platform_scope_requires_the_platform_role(ids, platform_ctx):
    """The reverse direction the CHECK also closes: a non-platform role cannot
    claim platform scope. Runs on the platform path since the tuple involves the
    NIL tenant, which app_runtime cannot write anyway."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO memberships (user_id, partner_id, scope_type, scope_id, role) "
            "VALUES (:u, :nil, 'platform', :nil, 'company_admin')",
            u=str(ids.platform_admin), nil=str(ids.nil))


def test_wellformed_platform_admin_membership_is_allowed(ids, platform_ctx):
    """The constraint must be tight, not merely refusing: a correctly anchored
    platform_super_admin (NIL tenant, platform scope, NIL scope_id) still
    inserts. The seeded ops@platform.test already is one; add a second user to
    prove the rule, not the seed."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        uid = uuid.uuid4()
        c.execute(text(
            "INSERT INTO users (id, email, partner_id, billing_source) "
            "VALUES (:u, :e, :nil, 'partner')"),
            {"u": str(uid), "e": f"ops-{uid}@platform.test", "nil": str(ids.nil)})
        c.execute(text(
            "INSERT INTO memberships (user_id, partner_id, scope_type, scope_id, role) "
            "VALUES (:u, :nil, 'platform', :nil, 'platform_super_admin')"),
            {"u": str(uid), "nil": str(ids.nil)})
        sp.rollback()


# --- #6: status enums and their correlated timestamps -----------------------

def test_connector_verified_requires_verified_at(ids, platform_ctx):
    """The specific inconsistency the audit named: verified with no timestamp,
    which verified_kinds() treats as usable."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO connectors (partner_id, kind, status, verified_at) "
            "VALUES (:a, 'slack', 'verified', NULL)",
            a=str(ids.partner_a))


def test_connector_illegal_status_is_refused(ids, platform_ctx):
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO connectors (partner_id, kind, status) "
            "VALUES (:a, 'slack', 'bogus')",
            a=str(ids.partner_a))


def test_invitation_accepted_requires_accepted_at(ids, platform_ctx):
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO invitations (partner_id, user_id, email, token_hash, status, "
            "expires_at, accepted_at) "
            "VALUES (:a, :u, 'x@y.test', :h, 'accepted', now() + interval '1 day', NULL)",
            a=str(ids.partner_a), u=str(ids.user_a), h=uuid.uuid4().hex + uuid.uuid4().hex)


def test_connector_verified_with_timestamp_is_allowed(ids, platform_ctx):
    """Tightness check for the correlation: the legal combination still writes."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        c.execute(text(
            "INSERT INTO connectors (partner_id, kind, status, verified_at) "
            "VALUES (:a, 'gmail', 'verified', now())"),
            {"a": str(ids.partner_a)})
        sp.rollback()
