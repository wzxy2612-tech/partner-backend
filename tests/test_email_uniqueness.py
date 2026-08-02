"""Global email uniqueness across the RLS visibility boundary (audit #7).

users.email is globally unique (0001 baseline), but the partner path can only
SEE its own tenant. So validate reported a row as clean while the address
already belonged to another partner -- or to a direct customer -- and the
conflict surfaced as an IntegrityError at INSERT, mid-batch, as a 500.

Three layers, and each is tested for both what it catches and what it must not
disclose:

  1. validate resolves existence on the PLATFORM path, so a cross-tenant clash
     is a clean per-row error before anything is written.
  2. the error wording is identical regardless of who holds the address --
     otherwise the endpoint becomes an enumeration oracle for other tenants'
     customer lists.
  3. the precheck narrows the race but cannot close it, so a unique violation is
     translated to a typed error -> 409, and only for THAT constraint.

The concurrency test uses two real connections; a single rolled-back
transaction cannot observe another's commit and so cannot exercise a race.
"""
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.services import onboarding
from app.services.onboarding import EmailAlreadyRegistered, _is_email_conflict


def _csv(email, company="Company A", role="read_only", name="X"):
    return f"email,name,role,company\n{email},{name},{role},{company}\n"


# --- 1. the conflict is visible at validate, before any write ---------------

def _precheck(platform_orm, rows):
    """What the router does before opening the partner transaction."""
    emails = {(r.get("email") or "").lower() for r in rows if (r.get("email") or "").strip()}
    with platform_orm() as pdb:
        return onboarding.taken_emails(pdb, emails)


def test_validate_flags_an_email_held_by_another_partner(ids, partner_orm, platform_orm):
    """Partner B's address, offered to Partner A. RLS hides B's users from A, so
    this passed validation and failed at INSERT."""
    with platform_orm() as pdb:          # B's row is only visible here
        email = pdb.execute(text("SELECT email FROM users WHERE id = :u"),
                            {"u": str(ids.user_b)}).scalar_one()
    rows = onboarding.parse_csv(_csv(email))
    taken = _precheck(platform_orm, rows)
    with partner_orm(ids.partner_a) as db:
        report = onboarding.validate(db, rows, taken)
    assert report.has_errors
    assert any("already registered" in e for e in report.rows[0].errors)


def test_validate_flags_a_direct_customers_email(ids, partner_orm, platform_orm):
    """The other cross-boundary case: the address belongs to a direct Stripe
    customer on the nil tenant, invisible to every partner."""
    rows = onboarding.parse_csv(_csv("direct@customer.test"))
    taken = _precheck(platform_orm, rows)
    with partner_orm(ids.partner_a) as db:
        report = onboarding.validate(db, rows, taken)
    assert report.has_errors
    assert any("already registered" in e for e in report.rows[0].errors)


def test_validate_writes_nothing_when_it_flags(ids, partner_orm, platform_ctx, platform_orm):
    """Two-phase onboarding's contract: validate is a dry run. A cross-tenant
    clash must not change that."""
    with platform_ctx() as c:
        before = c.execute(text("SELECT count(*) FROM users")).scalar_one()
    rows = onboarding.parse_csv(_csv("direct@customer.test"))
    taken = _precheck(platform_orm, rows)
    with partner_orm(ids.partner_a) as db:
        onboarding.validate(db, rows, taken)
    with platform_ctx() as c:
        assert c.execute(text("SELECT count(*) FROM users")).scalar_one() == before


# --- 2. the error must not say WHO holds the address ------------------------

def test_error_wording_is_identical_for_own_and_foreign_conflicts(ids, partner_orm, platform_orm):
    """The enumeration guard.

    If 'exists in your partner' and 'exists elsewhere' read differently, the
    endpoint answers "does this address exist in some other tenant?" one address
    at a time -- partner A could walk partner B's customer list. Both cases must
    be indistinguishable in the response."""
    with partner_orm(ids.partner_a) as db:
        own = db.execute(text("SELECT email FROM users WHERE id = :u"),
                         {"u": str(ids.user_a)}).scalar_one()
    own_rows = onboarding.parse_csv(_csv(own))
    foreign_rows = onboarding.parse_csv(_csv("direct@customer.test"))
    own_taken = _precheck(platform_orm, own_rows)
    foreign_taken = _precheck(platform_orm, foreign_rows)
    with partner_orm(ids.partner_a) as db:
        own_report = onboarding.validate(db, own_rows, own_taken)
        foreign_report = onboarding.validate(db, foreign_rows, foreign_taken)

    own_errs = [e for e in own_report.rows[0].errors if "registered" in e]
    foreign_errs = [e for e in foreign_report.rows[0].errors if "registered" in e]
    assert own_errs and foreign_errs
    assert own_errs == foreign_errs, (
        f"wording differs and leaks ownership: {own_errs} vs {foreign_errs}")


# --- 3. the backstop: only the email constraint becomes a 409 ---------------

def test_only_the_email_constraint_is_reinterpreted():
    """A broad `except IntegrityError` would quietly turn the 0007 tenant
    composite FKs -- and the 0010 platform-tuple CHECK -- into '409 email
    conflict', hiding real isolation failures behind a benign status."""
    class _Diag:
        def __init__(self, n): self.constraint_name = n
    class _Orig:
        def __init__(self, n): self.diag = _Diag(n)

    def ie(name):
        e = IntegrityError("stmt", {}, Exception())
        e.orig = _Orig(name)
        return e

    assert _is_email_conflict(ie("users_email_key"))
    for other in ("fk_sessions_user_id_partner", "fk_workflows_company_id_partner",
                  "ck_membership_platform_tuple", "uq_users_id_partner"):
        assert not _is_email_conflict(ie(other)), other


def test_concurrent_claim_yields_one_success_and_one_conflict(ids, platform_engine):
    """The race the precheck cannot close.

    Two onboardings validate the same fresh address, both see it free, both
    INSERT. The database decides; the loser must become a typed conflict (-> 409)
    rather than an unhandled IntegrityError (-> 500). Real connections, because
    one transaction cannot observe another's commit.
    """
    email = f"race-{uuid.uuid4().hex[:8]}@t.test"
    pid = ids.partner_a

    c1 = platform_engine.connect()
    c2 = platform_engine.connect()
    try:
        # Both "validated" the address as free at this point.
        assert onboarding.taken_emails(c1, {email}) == set()

        c1.execute(text(
            "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
            "VALUES (:i, :e, :p, 'partner', false)"),
            {"i": str(uuid.uuid4()), "e": email, "p": str(pid)})
        c1.commit()

        with pytest.raises(IntegrityError) as exc:
            c2.execute(text(
                "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
                "VALUES (:i, :e, :p, 'partner', false)"),
                {"i": str(uuid.uuid4()), "e": email, "p": str(pid)})
            c2.commit()
        c2.rollback()

        # And that violation is the one provision() translates to a 409.
        assert _is_email_conflict(exc.value), (
            "the losing insert must be recognised as the email conflict, or it "
            "surfaces as a 500")
    finally:
        c1.close(); c2.close()
        with platform_engine.connect() as c:
            c.execute(text("DELETE FROM users WHERE email = :e"), {"e": email})
            c.commit()
