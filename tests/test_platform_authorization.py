"""Platform authorization: who may operate the platform, and who may not.

Two principals sit on the platform tenant and differ in exactly one thing:

    direct@customer.test   nil tenant, no grants
    ops@platform.test      nil tenant, platform_super_admin grant

Everything that used to be decided by "has no tenant" now has to be decided by
the grant, and this pair is the discriminator. If a future change re-collapses
the two facts, the direct customer starts passing these tests.

The seeded pair only became expressible in 0009: memberships FKs to partners,
so before the platform tenant was a row there was nowhere to put a platform
grant -- which is the reason the code inferred privilege from the absence of a
tenant in the first place.
"""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError, IntegrityError

from app.auth.sessions import issue_session
from app.auth.principal import authenticate
from app.models.enums import Role


# --- the escalation, from both sides ----------------------------------------

def test_direct_customer_is_not_a_platform_admin(ids, platform_orm):
    """The bug, stated as an assertion. A paying Stripe customer shares the nil
    tenant with the platform because that is where tenant-less rows live; it
    conferred the right to suspend arbitrary partners and run cross-tenant
    jobs."""
    with platform_orm() as db:
        p = authenticate(db, issue_session(db, user_id=ids.direct_user, partner_id=ids.nil))
    assert p.is_platform_path is True
    assert p.is_platform_admin is False
    assert not p.has_role(Role.platform_super_admin)


def test_platform_admin_is_recognised(ids, platform_orm):
    """And the fix must not have simply locked the door: a real grant works."""
    with platform_orm() as db:
        p = authenticate(db, issue_session(db, user_id=ids.platform_admin, partner_id=ids.nil))
    assert p.is_platform_path is True
    assert p.is_platform_admin is True


def test_partner_admin_is_not_a_platform_admin(ids, platform_orm):
    """The third case: full privileges inside a tenant, none over the platform.
    partner_super_admin holds every Permission, so a check written against the
    permission set rather than the role would wrongly admit it."""
    with platform_orm() as db:
        p = authenticate(db, issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a))
    assert p.is_platform_path is False
    assert p.is_platform_admin is False


def test_require_platform_admits_only_the_admin(ids, platform_orm):
    """The dependency itself, which had no test at all -- the entire suite calls
    services directly, so nothing exercised the gate that was standing open."""
    from fastapi import HTTPException
    from app.deps import require_platform

    with platform_orm() as db:
        admin = authenticate(db, issue_session(db, user_id=ids.platform_admin, partner_id=ids.nil))
        direct = authenticate(db, issue_session(db, user_id=ids.direct_user, partner_id=ids.nil))
        tenant = authenticate(db, issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a))

    assert require_platform(admin) is admin
    for principal in (direct, tenant):
        with pytest.raises(HTTPException) as exc:
            require_platform(principal)
        assert exc.value.status_code == 403


# --- the platform tenant is structural --------------------------------------

def test_platform_tenant_row_exists(ids, platform_ctx):
    with platform_ctx() as c:
        row = c.execute(text("SELECT status FROM partners WHERE id = :nil"),
                        {"nil": str(ids.nil)}).first()
    assert row is not None, "0009 should have created the platform tenant"
    assert row.status == "active"


def test_platform_tenant_cannot_be_deleted(ids, platform_ctx):
    """Not merely 'nothing deletes it today'. The FKs make it undeletable only
    while a direct customer exists; the trigger makes it undeletable full
    stop."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        with pytest.raises(DatabaseError):
            c.execute(text("DELETE FROM partners WHERE id = :nil"), {"nil": str(ids.nil)})
        sp.rollback()


def test_ordinary_partners_are_still_deletable(ids, platform_ctx):
    """The trigger must fire on one row, not on the table. The purge job deletes
    real partners and has to keep working."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        c.execute(text("DELETE FROM users WHERE partner_id = :b"), {"b": str(ids.partner_b)})
        c.execute(text("DELETE FROM partners WHERE id = :b"), {"b": str(ids.partner_b)})
        sp.rollback()


def test_partner_delete_is_restricted_while_users_remain(ids, platform_ctx):
    """ON DELETE RESTRICT, not CASCADE. A purge path that forgets to remove
    users first gets an error instead of silently deleting accounts."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        with pytest.raises(IntegrityError):
            c.execute(text("DELETE FROM partners WHERE id = :b"), {"b": str(ids.partner_b)})
        sp.rollback()


def test_every_partner_id_now_references_a_real_partner(ids, platform_ctx):
    """The invariant 0009 buys: users and sessions were the last partner_id
    columns with no foreign key, because the nil sentinel had nothing to point
    at. Asserted against the catalog so a future table cannot quietly reopen the
    gap."""
    with platform_ctx() as c:
        unbacked = c.execute(text("""
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid
                 AND a.attname = 'partner_id' AND a.attnum > 0 AND NOT a.attisdropped
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND NOT EXISTS (
                SELECT 1 FROM pg_constraint fk
                WHERE fk.conrelid = c.oid AND fk.contype = 'f'
                  AND a.attnum = ANY (fk.conkey)
              )
        """)).scalars().all()
    assert unbacked == [], f"partner_id with no FK: {unbacked}"


# --- the platform tenant has no partner lifecycle ---------------------------

def test_platform_tenant_cannot_be_suspended(ids, platform_orm):
    from app.services.partners import suspend_partner, activate_partner
    with platform_orm() as db:
        with pytest.raises(ValueError):
            suspend_partner(db, ids.nil)
        with pytest.raises(ValueError):
            activate_partner(db, ids.nil)
