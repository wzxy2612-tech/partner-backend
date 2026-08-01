"""Invitation redemption closes the loop with auth: set password + activate."""
from sqlalchemy import text

from app.services import onboarding
from app.services.email import OutboxEmailSender
from app.auth.password import verify_password

CSV = "email,name,role,company\nnewbie@x.test,Newbie,author,Company A\n"


def _provision_one(db, ids):
    outbox = OutboxEmailSender()
    _, result = onboarding.onboard(db, ids.partner_a, CSV, sender=outbox)
    assert result and len(result.created_user_ids) == 1
    return outbox.sent[0]  # (email, token)


def test_accept_sets_password_and_activates(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
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


def test_accept_cannot_be_reused(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        _, token = _provision_one(db, ids)
        assert onboarding.accept_invitation(db, token, "pw1") is True
        assert onboarding.accept_invitation(db, token, "pw2") is False  # already accepted
