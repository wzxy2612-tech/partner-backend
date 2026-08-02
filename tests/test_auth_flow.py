"""Auth flow against the DB (platform path): issue -> resolve -> revoke."""
from datetime import timedelta

from app.auth.sessions import issue_session, revoke_token
from app.auth.principal import authenticate
from app.models.enums import Role, PartnerStatus


def test_login_resolves_partner_principal(ids, platform_orm):
    with platform_orm() as db:
        token = issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a)
        p = authenticate(db, token)
    assert p is not None
    assert p.user_id == ids.user_a
    assert p.partner_id == ids.partner_a
    assert p.is_platform_path is False
    assert p.partner_status == PartnerStatus.active
    assert p.has_role(Role.partner_super_admin)


def test_direct_user_is_on_platform_path_but_is_not_an_admin(ids, platform_orm):
    """A direct (Stripe) customer has no tenant, so it routes onto the platform
    DB path -- and that is ALL it means. It previously also made them a platform
    operator, because one boolean carried both facts.

    This test used to assert only the first half; asserting the second half is
    what turns the fix into a regression guard."""
    with platform_orm() as db:
        token = issue_session(db, user_id=ids.direct_user, partner_id=ids.nil)
        p = authenticate(db, token)
    assert p is not None
    assert p.is_platform_path is True      # routing fact
    assert p.is_platform_admin is False    # authorization fact
    assert p.partner_status is None


def test_missing_and_bad_tokens_are_rejected(ids, platform_orm):
    with platform_orm() as db:
        assert authenticate(db, None) is None
        assert authenticate(db, "not-a-real-token") is None


def test_revoked_token_stops_working(ids, platform_orm):
    with platform_orm() as db:
        token = issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a)
        assert authenticate(db, token) is not None
        assert revoke_token(db, token) == 1
        db.expire_all()  # a fresh request reads fresh; simulate that here
        assert authenticate(db, token) is None


def test_expired_token_is_rejected(ids, platform_orm):
    with platform_orm() as db:
        token = issue_session(db, user_id=ids.user_a, partner_id=ids.partner_a,
                              ttl=timedelta(seconds=-1))
        assert authenticate(db, token) is None
