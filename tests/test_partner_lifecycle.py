"""Suspension / activation / domain deactivation, each with token revocation."""
from datetime import datetime, timezone

from sqlalchemy import text

from app.auth.sessions import issue_session
from app.auth.principal import authenticate
from app.services.partners import suspend_partner, activate_partner, deactivate_domain
from app.models.enums import PartnerStatus


def test_suspend_revokes_all_partner_sessions_and_stamps_retention(ids, platform_orm):
    with platform_orm() as db:
        token = issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a)
        revoked = suspend_partner(db, ids.partner_a)
        assert revoked >= 1

        status, susp_at, retain = db.execute(
            text("SELECT status, suspended_at, suspension_retention_until "
                 "FROM partners WHERE id = :p"), {"p": str(ids.partner_a)}).one()
        assert status == "suspended"
        assert susp_at is not None
        # retention window is ~60 days out
        assert (retain - datetime.now(timezone.utc)).days >= 59

        db.expire_all()
        assert authenticate(db, token) is None  # session was revoked by suspension


def test_activate_clears_suspension(ids, platform_orm):
    with platform_orm() as db:
        suspend_partner(db, ids.partner_a)
        activate_partner(db, ids.partner_a)
        status, susp_at, retain = db.execute(
            text("SELECT status, suspended_at, suspension_retention_until "
                 "FROM partners WHERE id = :p"), {"p": str(ids.partner_a)}).one()
    assert status == "active"
    assert susp_at is None and retain is None


def test_deactivate_domain_is_partner_scoped(ids, platform_orm):
    # partner A has 3 users on @partner.test (a/ca/ro); partner B's b@partner.test
    # shares the domain but must be untouched.
    with platform_orm() as db:
        token_a = issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a)
        count = deactivate_domain(db, ids.partner_a, "partner.test")
        assert count == 3  # all of partner A's @partner.test users, none of B's

        a_active = db.execute(text("SELECT is_active FROM users WHERE id = :u"),
                              {"u": str(ids.user_a)}).scalar_one()
        b_active = db.execute(text("SELECT is_active FROM users WHERE id = :u"),
                              {"u": str(ids.user_b)}).scalar_one()
        assert a_active is False
        assert b_active is True  # different partner, untouched

        db.expire_all()
        assert authenticate(db, token_a) is None  # deactivated user's session killed
