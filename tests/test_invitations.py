"""Invitation redemption closes the loop with auth: set password + activate."""
from sqlalchemy import text

from app.services import onboarding, outbox
from app.services.email import OutboxEmailSender
from app.auth.password import verify_password

CSV = "email,name,role,company\nnewbie@x.test,Newbie,author,Company A\n"


def _provision_one(db, ids):
    """Provision one user and obtain the token the way the real system does:
    from the outbox, after the invitation exists.

    This used to read the token out of an injected sender, because provision()
    sent the mail itself. It cannot any more -- the token now travels as
    encrypted payload on an outbox event, and dispatching is what turns it back
    into something a recipient could receive."""
    _, result = onboarding.onboard(db, ids.partner_a, CSV)
    assert result and len(result.created_user_ids) == 1
    captured = OutboxEmailSender()
    dispatched = outbox.dispatch_pending(db, captured)
    assert len(dispatched.sent) == 1
    return captured.sent[0]  # (email, token)


def test_accept_sets_password_and_activates(ids, platform_orm):
    with platform_orm() as db:
        email, token = _provision_one(db, ids)
        active, pw = db.execute(
            text("SELECT is_active, hashed_password FROM users WHERE email = :e"),
            {"e": email}).one()
        assert active is False and pw is None       # starts inactive, no password

        assert onboarding.accept_invitation(db, token, "brand-new-pw") is True

        active2, pw2 = db.execute(
            text("SELECT is_active, hashed_password FROM users WHERE email = :e"),
            {"e": email}).one()
        status = db.execute(
            text("SELECT status FROM invitations WHERE email = :e"), {"e": email}).scalar_one()
    assert active2 is True
    assert pw2 is not None and verify_password("brand-new-pw", pw2)
    assert status == "accepted"


def test_accept_rejects_unknown_token(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        assert onboarding.accept_invitation(db, "not-a-token", "x") is False


def test_accept_cannot_be_reused(ids, platform_orm):
    with platform_orm() as db:
        _, token = _provision_one(db, ids)
        assert onboarding.accept_invitation(db, token, "pw1") is True
        assert onboarding.accept_invitation(db, token, "pw2") is False  # already accepted
