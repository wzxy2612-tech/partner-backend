"""Two-step CSV onboarding: validate writes nothing; commit is atomic."""
import pytest
from sqlalchemy import text

from app.services import onboarding
from app.services.email import OutboxEmailSender

GOOD_CSV = (
    "email,name,role,company\n"
    "alice@x.test,Alice,author,Company A\n"
    "bob@x.test,Bob,read_only,Company A2\n"
)

BAD_CSV = (
    "email,name,role,company\n"
    "not-an-email,NoEmail,author,Company A\n"   # 1: bad email
    "carol@x.test,Carol,wizard,Company A\n"     # 2: bad role
    "dave@x.test,Dave,author,Nowhere Co\n"      # 3: unknown company
    "eve@x.test,Eve,author,Company A\n"         # 4: valid
    "eve@x.test,Eve,read_only,Company A\n"      # 5: duplicate within file
    "a@partner.test,Existing,author,Company A\n"  # 6: email already exists
)


def test_validate_good_csv_clean_and_no_writes(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        before = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        report = onboarding.validate(db, onboarding.parse_csv(GOOD_CSV))
        after = db.execute(text("SELECT count(*) FROM users")).scalar_one()
    assert not report.has_errors
    assert len(report.valid_rows) == 2
    assert before == after  # validation never writes


def test_validate_flags_every_bad_row(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        report = onboarding.validate(db, onboarding.parse_csv(BAD_CSV))
    assert report.has_errors
    errs = {r.row: r.errors for r in report.rows}
    assert any("email" in e for e in errs[1])
    assert any("invalid role" in e for e in errs[2])
    assert any("unknown company" in e for e in errs[3])
    assert errs[4] == []                                   # first eve is fine
    assert any("duplicate" in e for e in errs[5])
    assert any("already exists" in e for e in errs[6])


def test_commit_provisions_users_memberships_invites(ids, partner_orm):
    outbox = OutboxEmailSender()
    with partner_orm(ids.partner_a) as db:
        u0 = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        report, result = onboarding.onboard(db, ids.partner_a, GOOD_CSV, sender=outbox)
        u1 = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        invites = db.execute(text("SELECT count(*) FROM invitations")).scalar_one()
    assert not report.has_errors and result is not None
    assert len(result.created_user_ids) == 2
    assert u1 - u0 == 2
    assert invites == 2
    assert len(outbox.sent) == 2


class _BoomSender:
    def __init__(self):
        self.calls = 0

    def send_invitation(self, email, token):
        self.calls += 1
        if self.calls == 2:          # fail partway through the batch
            raise RuntimeError("smtp down")


def test_commit_rolls_back_entire_batch_on_failure(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        before = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        report = onboarding.validate(db, onboarding.parse_csv(GOOD_CSV))
        with pytest.raises(RuntimeError):
            onboarding.provision(db, ids.partner_a, report, _BoomSender())
        after = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        invites = db.execute(text("SELECT count(*) FROM invitations")).scalar_one()
    assert after == before   # row 1 was undone along with the failed row 2
    assert invites == 0
