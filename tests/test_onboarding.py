"""Two-step CSV onboarding: validate writes nothing; commit is atomic."""
import pytest
from sqlalchemy import text

from app.services import onboarding

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
    "a@partner.test,Existing,author,Company A\n"  # 6: email already registered
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
    # Wording is "already registered", identical whether the address belongs to
    # this partner, another partner, or a direct customer -- the old
    # "already exists for this partner" told the caller which, turning the
    # endpoint into an enumeration oracle for other tenants' customer lists.
    assert any("already registered" in e for e in errs[6])


def test_commit_provisions_users_memberships_invites(ids, platform_orm):
    with platform_orm() as db:
        u0 = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        report, result = onboarding.onboard(db, ids.partner_a, GOOD_CSV)
        u1 = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        # Scoped explicitly. This test moved to the platform path when 0019 took
        # SELECT on outbox_events away from the runtime role, and BYPASSRLS means
        # an unscoped count is a count of every tenant -- which happens to be
        # right only while the seed fixture leaves the table empty.
        invites = db.execute(text(
            "SELECT count(*) FROM invitations WHERE partner_id = :p"),
            {"p": str(ids.partner_a)}).scalar_one()
        events = db.execute(text(
            "SELECT count(*) FROM outbox_events "
            "WHERE partner_id = :p AND status = 'pending'"),
            {"p": str(ids.partner_a)}).scalar_one()
    assert not report.has_errors and result is not None
    assert len(result.created_user_ids) == 2
    assert u1 - u0 == 2
    assert invites == 2
    # One queued event per invitation, written in the same transaction. Nothing
    # was sent: provision() no longer has a way to send.
    assert events == 2


def test_commit_rolls_back_entire_batch_on_failure(ids, platform_orm, monkeypatch):
    """The batch is still all-or-nothing -- and now the mail is inside that
    guarantee rather than beside it.

    This test used to inject a sender that raised on row 2, proving the database
    rolled back. What it could not prove, and what was actually broken, is that
    row 1's email had ALREADY GONE OUT and could not be recalled: the recipient
    held a token for a record that no longer existed. The failure is injected at
    the outbox write instead, because sending is no longer something provision()
    can do."""
    def boom(db, **kwargs):
        boom.calls += 1
        if boom.calls == 2:
            raise RuntimeError("outbox write failed")
        return None
    boom.calls = 0
    monkeypatch.setattr(onboarding.outbox, "enqueue_invitation", boom)

    with platform_orm() as db:
        before = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        report = onboarding.validate(db, onboarding.parse_csv(GOOD_CSV))
        with pytest.raises(RuntimeError):
            onboarding.provision(db, ids.partner_a, report)
        after = db.execute(text("SELECT count(*) FROM users")).scalar_one()
        invites = db.execute(text(
            "SELECT count(*) FROM invitations WHERE partner_id = :p"),
            {"p": str(ids.partner_a)}).scalar_one()
        events = db.execute(text(
            "SELECT count(*) FROM outbox_events WHERE partner_id = :p"),
            {"p": str(ids.partner_a)}).scalar_one()
    assert after == before      # row 1 undone along with the failed row 2
    assert invites == 0
    assert events == 0          # and no queued mail survives the rollback
