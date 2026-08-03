"""The active-state gate, on the paths that do not have RLS.

partner_is_active() has existed since 0011 with exactly one consumer: twelve
row-security policies. Everything that legitimately runs on the platform
connection -- login, invitation redemption, outbox dispatch, lifecycle
transitions -- is BYPASSRLS, and therefore ran with no gate at all. Four
separate audit findings (#4, #5, #8, #9) were four outlets of that one fact.

These tests cover the outlets 0015 closed. Each one is a reported live
reproduction, not a hypothetical.

WHAT IS DELIBERATELY NOT HERE

A suspended-partner login test. test_toctou_lifecycle.py already owns that
case and exercises the rewritten code path unchanged, so a copy here would
assert the same thing twice and give two places to update when the rule moves.
What IS here are the two login cases that the rewrite newly put at risk: an
active partner and a direct customer must still get in, because swapping an
inline status comparison for a function call breaks those silently if the
function does not resolve the way the comparison did.
"""
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.auth.tokens import hash_token
from app.services.onboarding import accept_invitation
from app.services.partners import suspend_partner, deactivate_domain

PASSWORD = "correct-horse-battery-staple"
INVITEE_DOMAIN = "invitee.test"


def _pending_invite(db, partner_id, *, email=None):
    """An inactive invited user, a pending invitation, and its queued mail.

    Mirrors what provision() writes, without going through the CSV path: these
    tests are about what happens to an outstanding invitation afterwards, and
    building it directly keeps a failure here from being a failure in parsing.
    """
    email = email or f"invitee-{uuid.uuid4().hex[:8]}@{INVITEE_DOMAIN}"
    uid, inv_id, ev_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    token = f"token-{uuid.uuid4().hex}"

    db.execute(text(
        "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
        "VALUES (:u, :e, :p, 'partner', false)"),
        {"u": str(uid), "e": email, "p": str(partner_id)})
    db.execute(text(
        "INSERT INTO invitations (id, partner_id, user_id, email, token_hash, "
        "status, expires_at) VALUES "
        "(:i, :p, :u, :e, :h, 'pending', now() + interval '7 days')"),
        {"i": str(inv_id), "p": str(partner_id), "u": str(uid), "e": email,
         "h": hash_token(token)})
    db.execute(text(
        "INSERT INTO outbox_events (id, partner_id, invitation_id, event_type, "
        "recipient, token_ciphertext, token_nonce, key_version, status) VALUES "
        "(:v, :p, :i, 'invitation.created', :e, :c, :n, 1, 'pending')"),
        {"v": str(ev_id), "p": str(partner_id), "i": str(inv_id), "e": email,
         "c": b"stand-in-ciphertext", "n": b"stand-in-nc"})

    return SimpleNamespace(token=token, user_id=uid, invitation_id=inv_id,
                           event_id=ev_id, email=email)


def _event(db, event_id):
    return db.execute(text(
        "SELECT status, token_ciphertext, token_nonce, last_error "
        "FROM outbox_events WHERE id = :v"), {"v": str(event_id)}).one()


def _invitation_status(db, invitation_id):
    return db.execute(text("SELECT status FROM invitations WHERE id = :i"),
                      {"i": str(invitation_id)}).scalar_one()


# --- the anchor -------------------------------------------------------------

def test_a_pending_invitation_still_redeems_when_the_partner_is_active(ids, platform_orm):
    """Positive control for everything below, and a regression guard in its own
    right.

    Every other redemption test asserts a refusal, and all of them pass for free
    if _pending_invite builds something unredeemable or if the new
    partner_is_active() clause never matches. This one fails in exactly those
    cases. It also covers the plainest way 0015 could have broken the product:
    adding a condition to the claim that refuses everyone.
    """
    with platform_orm() as db:
        inv = _pending_invite(db, ids.partner_a)
        assert accept_invitation(db, inv.token, PASSWORD) is True
        assert _invitation_status(db, inv.invitation_id) == "accepted"
        assert db.execute(text("SELECT is_active FROM users WHERE id = :u"),
                          {"u": str(inv.user_id)}).scalar_one() is True


# --- #9: suspension ---------------------------------------------------------

def test_a_suspended_partners_invitation_cannot_be_redeemed(ids, platform_orm):
    """Reported live: suspend, redeem an old token, user activated. Reactivate
    the partner later and that user could log in -- an account created during a
    suspension, surviving it.

    Redemption runs on the platform connection, so the twelve policies that
    would have refused this are all bypassed. The gate has to be written into
    the claim itself.
    """
    with platform_orm() as db:
        inv = _pending_invite(db, ids.partner_a)
        suspend_partner(db, ids.partner_a)

        assert accept_invitation(db, inv.token, PASSWORD) is False
        assert db.execute(text("SELECT is_active FROM users WHERE id = :u"),
                          {"u": str(inv.user_id)}).scalar_one() is False


def test_suspension_revokes_the_invitation_permanently(ids, platform_orm):
    """Revoked has to outlive the suspension.

    If suspension only made redemption fail while the status stayed `pending`,
    reactivating the partner would hand the token back its power. The invitation
    is moved to a terminal state instead, so the answer does not depend on what
    the partner's status happens to be at redemption time.
    """
    with platform_orm() as db:
        inv = _pending_invite(db, ids.partner_a)
        suspend_partner(db, ids.partner_a)
        assert _invitation_status(db, inv.invitation_id) == "revoked"

        db.execute(text("UPDATE partners SET status = 'active' WHERE id = :p"),
                   {"p": str(ids.partner_a)})
        assert accept_invitation(db, inv.token, PASSWORD) is False


# --- #9: domain deactivation ------------------------------------------------

def test_a_domain_deactivated_invitee_cannot_redeem(ids, platform_orm):
    """The filter that caused this said `AND is_active = true`.

    An invited user is inactive from creation until redemption, so that filter
    skipped precisely the accounts whose access had not landed yet -- the scan
    reported zero users affected and the pending token stayed live. Inactive is
    not a marker of "already handled".
    """
    with platform_orm() as db:
        inv = _pending_invite(db, ids.partner_a)
        deactivate_domain(db, ids.partner_a, INVITEE_DOMAIN)

        assert _invitation_status(db, inv.invitation_id) == "revoked"
        assert accept_invitation(db, inv.token, PASSWORD) is False


def test_domain_deactivation_leaves_other_domains_alone(ids, platform_orm):
    """The counterpart to the widened scan. Broadening it from active users to
    every user on the domain must not broaden it across domains as well -- that
    was the '%' wildcard bug in a different costume.
    """
    with platform_orm() as db:
        target = _pending_invite(db, ids.partner_a)
        bystander = _pending_invite(db, ids.partner_a,
                                    email=f"keep-{uuid.uuid4().hex[:8]}@other.test")
        deactivate_domain(db, ids.partner_a, INVITEE_DOMAIN)

        assert _invitation_status(db, target.invitation_id) == "revoked"
        assert _invitation_status(db, bystander.invitation_id) == "pending"


# --- the queued mail --------------------------------------------------------

def test_revocation_terminates_the_queued_mail_and_clears_the_secret(ids, platform_orm):
    """Revoking the invitation without touching the outbox leaves the token
    both deliverable and recoverable.

    The dispatcher's claim query does not consult invitations, so a pending
    event whose invitation is revoked would still be sent. And the row would
    still hold ciphertext for a credential nobody can use -- a liability with no
    remaining purpose.
    """
    with platform_orm() as db:
        inv = _pending_invite(db, ids.partner_a)
        suspend_partner(db, ids.partner_a)

        ev = _event(db, inv.event_id)
        assert ev.status == "failed"
        assert ev.token_ciphertext is None
        assert ev.token_nonce is None
        assert ev.last_error  # says why, without naming the recipient or token


# --- #4: the platform tenant ------------------------------------------------

def test_the_platform_tenant_cannot_be_domain_deactivated(ids, platform_orm):
    """suspend and activate have refused NIL since 0009. This path did not, and
    deactivating a domain on the platform tenant took out direct customers, who
    have no partner lifecycle to be subject to.
    """
    with platform_orm() as db:
        with pytest.raises(ValueError):
            deactivate_domain(db, ids.nil, "customer.test")


# --- #8: billing ------------------------------------------------------------

def test_an_active_partner_can_still_set_billing_through_the_function(ids, partner_ctx):
    """The other half of the revoke. Taking away UPDATE (billing_contact_email)
    without a working replacement would break the feature silently, and every
    refusal test below would still pass.

    This is also the only behavioural check on the tenant expression inside the
    function: it is the sixth hand-written copy of the GUC lookup, and a typo in
    it would make the function return false for everyone -- which looks exactly
    like a correct refusal from the outside.
    """
    with partner_ctx(ids.partner_a) as c:
        ok = c.execute(text(
            "SELECT public.set_active_partner_billing_contact('billing@a.test')"
        )).scalar_one()
        assert ok is True
        assert c.execute(text(
            "SELECT billing_contact_email FROM partners WHERE id = :p"),
            {"p": str(ids.partner_a)}).scalar_one() == "billing@a.test"


def test_a_suspended_partner_cannot_set_billing(ids, partner_ctx, platform_engine):
    """The stale-request window. A principal resolved while active, an operator
    suspending mid-request, and the write landing anyway.

    Through the HTTP route this was already stopped, but by accident: enforce()
    reads `memberships`, which IS gated, so the principal loses its grant first.
    That protection lives in a different table's policy and would vanish the day
    the billing route got a cheaper authorization check. Here the database
    refuses on its own.
    """
    with platform_engine.begin() as c:
        c.execute(text(
            "UPDATE partners SET status = 'suspended', suspended_at = now(), "
            "suspension_retention_until = now() + interval '60 days' WHERE id = :p"),
            {"p": str(ids.partner_a)})
    try:
        with partner_ctx(ids.partner_a) as c:
            ok = c.execute(text(
                "SELECT public.set_active_partner_billing_contact('stale@a.test')"
            )).scalar_one()
            assert ok is False
            assert c.execute(text(
                "SELECT billing_contact_email FROM partners WHERE id = :p"),
                {"p": str(ids.partner_a)}).scalar_one() != "stale@a.test"
    finally:
        with platform_engine.begin() as c:
            c.execute(text(
                "UPDATE partners SET status = 'active', suspended_at = NULL, "
                "suspension_retention_until = NULL WHERE id = :p"),
                {"p": str(ids.partner_a)})


def test_the_runtime_role_can_no_longer_write_billing_directly(ids, partner_ctx):
    """If the column grant survived, the controlled function would be a
    suggestion. 0011 handed this column back precisely because the partners
    policy could not be gated; 0015 takes it away again and puts the gate in the
    function instead.
    """
    with partner_ctx(ids.partner_a) as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text(
                "UPDATE partners SET billing_contact_email = 'direct@a.test' "
                "WHERE id = :p"), {"p": str(ids.partner_a)})
    orig = exc.value.orig
    sqlstate = (getattr(orig, "sqlstate", None)
                or getattr(getattr(orig, "diag", None), "sqlstate", None))
    assert sqlstate == "42501", f"expected insufficient_privilege, got {sqlstate}"


# --- login, after the predicate moved ---------------------------------------

def test_login_still_admits_an_active_partners_user(ids):
    """login() now calls partner_is_active() instead of comparing status inline.
    The refusal case is covered in test_toctou_lifecycle; what is new here is
    that the function has to resolve and return true on the platform connection,
    where it runs as a BYPASSRLS role rather than under any policy.
    """
    from app.routers.auth import login, LoginBody
    assert login(LoginBody(email="a@partner.test", password=ids.pw_a)).token


def test_login_still_admits_a_direct_customer(ids, platform_engine):
    """Direct customers sit on the NIL platform tenant, which has no lifecycle.
    The partner check is skipped for them by an explicit `!= NIL` guard -- and
    if that guard were ever removed, partner_is_active(NIL) would decide the
    fate of every non-partner user in the system.
    """
    from app.routers.auth import login, LoginBody
    with platform_engine.connect() as c:
        email = c.execute(text("SELECT email FROM users WHERE id = :u"),
                          {"u": str(ids.direct_user)}).scalar_one()
    assert login(LoginBody(email=email, password=ids.pw_direct)).token
