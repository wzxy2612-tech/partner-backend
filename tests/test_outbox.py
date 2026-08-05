"""Transactional outbox: the guarantee, and its limits.

The claim two-phase onboarding makes is "all or nothing". Before the outbox that
was true of the database and false of the world: mail sent for row 1 could not be
recalled when row 2 failed, so a recipient held a token for a record that had
been rolled away. These tests pin the repaired boundary and, just as
deliberately, the places where the guarantee stops.

The first test is the one that matters. Everything else supports it.
"""
import uuid
import pytest
from sqlalchemy import text

from app.services import onboarding, outbox
from app.services.email import OutboxEmailSender
from app.services.outbox_crypto import build_aad, encrypt_token

CSV = ("email,name,role,company\n"
       "ob1@x.test,One,author,Company A\n"
       "ob2@x.test,Two,author,Company A\n")


class _Echo:
    """Raises with exactly what it was handed. Providers echo the request back
    in error bodies -- the address, the URL, the token -- so this is the shape
    of adversary the retry path actually meets."""
    def send_invitation(self, email, token):
        raise ValueError(f"provider rejected {email}: token {token} not accepted")


class _Boom:
    """A sender that always fails, for the retry and dead-letter paths."""
    def __init__(self, exc=RuntimeError("smtp down")):
        self.exc, self.calls = exc, 0

    def send_invitation(self, email, token):
        self.calls += 1
        raise self.exc


# --- the guarantee ----------------------------------------------------------

def test_rollback_leaves_no_invitation_and_nothing_to_send(ids, platform_orm):
    """The whole point. When the batch rolls back, the queued mail goes with it,
    because the event was written in the same transaction as the invitation.

    Previously the database rolled back and the already-sent mail did not --
    that asymmetry is what made "all or nothing" untrue."""
    with platform_orm() as db:
        sp = db.begin_nested()
        onboarding.onboard(db, ids.partner_a, CSV)
        assert db.execute(text(
            "SELECT count(*) FROM outbox_events WHERE partner_id = :p"),
            {"p": str(ids.partner_a)}).scalar_one() == 2
        sp.rollback()

        assert db.execute(text(
            "SELECT count(*) FROM outbox_events WHERE partner_id = :p"),
            {"p": str(ids.partner_a)}).scalar_one() == 0
        assert db.execute(text(
            "SELECT count(*) FROM invitations WHERE email LIKE 'ob%@x.test'"
        )).scalar_one() == 0

        # And a dispatcher run afterwards has nothing to deliver.
        captured = OutboxEmailSender()
        assert outbox.dispatch_pending(db, captured).total == 0
        assert captured.sent == []


def test_dispatch_delivers_committed_events(ids, platform_orm):
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        captured = OutboxEmailSender()
        result = outbox.dispatch_pending(db, captured)

    assert len(result.sent) == 2
    assert {e for e, _t in captured.sent} == {"ob1@x.test", "ob2@x.test"}
    assert all(tok for _e, tok in captured.sent), "a real token must be delivered"


def test_delivery_destroys_the_stored_secret(ids, platform_orm):
    """A sent event must not keep a redeemable token. 0013 enforces the pairing
    as a CHECK, so this also proves the dispatcher satisfies it."""
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        outbox.dispatch_pending(db, OutboxEmailSender())
        rows = db.execute(text(
            "SELECT status, token_ciphertext, token_nonce, sent_at "
            "FROM outbox_events")).all()

    assert rows and all(r.status == "sent" for r in rows)
    assert all(r.token_ciphertext is None and r.token_nonce is None for r in rows)
    assert all(r.sent_at is not None for r in rows)


# --- failure handling -------------------------------------------------------

def test_failure_keeps_the_payload_and_backs_off(ids, platform_orm):
    """A retry must still be possible, so the ciphertext survives a failure --
    and the next attempt is scheduled into the future rather than spun on."""
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        result = outbox.dispatch_pending(db, _Boom())
        assert len(result.retried) == 2

        rows = db.execute(text(
            "SELECT status, attempts, token_ciphertext, last_error, "
            "       available_at > now() AS deferred FROM outbox_events")).all()

    assert all(r.status == "pending" for r in rows)
    assert all(r.attempts == 1 for r in rows)
    assert all(r.token_ciphertext is not None for r in rows)
    assert all(r.deferred for r in rows), "retry must be scheduled, not immediate"
    # The TYPE, not the message. This line used to assert "smtp down" was
    # stored, which pinned the leak: it required the provider's own words to be
    # persisted, and a provider's words are whatever the provider decides to
    # echo back. The type is drawn from code, so it is ours to record.
    assert all(r.last_error == "RuntimeError: delivery failed" for r in rows)


def test_stored_error_never_contains_the_token(ids, platform_orm):
    """This test existed, passed, and did not catch the defect it is named for.

    Its adversary was _Boom, which raises RuntimeError("smtp down") -- a message
    with no token in it. Asserting the token was absent proved a property of the
    fixture, not of the code: nothing had put the token there because nothing
    had one to put. The sender is handed the plaintext token as an argument, so
    an adversary that echoes its arguments is the faithful one, and providers do
    exactly that in error bodies.
    """
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        peeked = _peek_tokens(db)
        tokens = {t for _e, t in peeked}
        outbox.dispatch_pending(db, _Echo())
        rows = db.execute(text(
            "SELECT recipient, last_error FROM outbox_events")).all()

    assert tokens, "no tokens to leak -- this test would pass vacuously"
    for row in rows:
        for tok in tokens:
            assert tok not in row.last_error
        # The address came from the same untrusted string. It is already in the
        # recipient column, so this is not new exposure -- but it is the same
        # text, and if it survived then so could anything else in it.
        assert row.recipient not in row.last_error


def test_the_failure_type_is_still_recorded(ids, platform_orm):
    """The opposite over-correction: storing nothing at all.

    An empty last_error makes a dead-lettered batch uninvestigable, and the
    first person who has to investigate one will put str(exc) back. Recording
    the type is what makes that unnecessary.
    """
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        outbox.dispatch_pending(db, _Echo())
        errors = db.execute(text(
            "SELECT last_error FROM outbox_events")).scalars().all()

    assert errors
    for err in errors:
        assert err.startswith("ValueError:"), err
        assert len(err) <= outbox.LAST_ERROR_MAX


def test_reaching_the_attempt_limit_dead_letters(ids, platform_orm):
    """Retrying forever is not a policy. At MAX_ATTEMPTS the event stops, keeps
    its history for inspection, and drops its secret material -- a permanently
    undeliverable row has no reason to remain redeemable."""
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        for _ in range(outbox.MAX_ATTEMPTS):
            db.execute(text("UPDATE outbox_events SET available_at = now() "
                            "WHERE status = 'pending'"))
            outbox.dispatch_pending(db, _Boom())

        rows = db.execute(text(
            "SELECT status, attempts, token_ciphertext FROM outbox_events")).all()

    assert all(r.status == "failed" for r in rows), [r.status for r in rows]
    assert all(r.attempts >= outbox.MAX_ATTEMPTS for r in rows)
    assert all(r.token_ciphertext is None for r in rows)


def test_unauthenticated_payload_dead_letters_immediately(ids, platform_orm):
    """A ciphertext that does not belong to its row cannot be fixed by retrying,
    so it must not consume attempts. This is the AAD binding observed from the
    dispatcher's side: moving a valid ciphertext onto another event makes it
    undeliverable rather than making it deliver someone else's token."""
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        ids_ = db.execute(text("SELECT id FROM outbox_events ORDER BY id")).scalars().all()
        # Re-encrypt a token under a DIFFERENT event's identity, then plant it.
        foreign_aad = build_aad(event_id=uuid.uuid4(), invitation_id=uuid.uuid4(),
                                partner_id=ids.partner_a,
                                event_type=outbox.EVENT_INVITATION_CREATED)
        # Three-tuple since the version travels with the ciphertext; the
        # planted row keeps whatever key_version it already had, which is
        # the point -- the AAD is what refuses it, not the key.
        ct, nonce, _kv = encrypt_token("some-token", foreign_aad)
        db.execute(text("UPDATE outbox_events SET token_ciphertext = :c, "
                        "token_nonce = :n WHERE id = :i"),
                   {"c": ct, "n": nonce, "i": str(ids_[0])})

        captured = OutboxEmailSender()
        result = outbox.dispatch_pending(db, captured)

        assert ids_[0] in result.dead_lettered
        assert not any(t == "some-token" for _e, t in captured.sent), \
            "a mis-bound payload must never be delivered"


# --- idempotence and concurrency -------------------------------------------

def test_a_sent_event_is_not_sent_again(ids, platform_orm):
    with platform_orm() as db:
        onboarding.onboard(db, ids.partner_a, CSV)
        first = outbox.dispatch_pending(db, OutboxEmailSender())
        second_capture = OutboxEmailSender()
        second = outbox.dispatch_pending(db, second_capture)

    assert len(first.sent) == 2
    assert second.total == 0 and second_capture.sent == []


def test_two_dispatchers_do_not_send_the_same_event(ids, platform_engine):
    """FOR UPDATE SKIP LOCKED. The second dispatcher must step over rows the
    first is holding -- not block, and above all not read and send them too.

    Everything here runs on its OWN committed connections, not on the
    partner_orm fixture. That fixture binds its session to a connection whose
    transaction it rolls back unconditionally in `finally`, so a db.commit()
    inside it does not make anything visible to another connection -- my first
    version did exactly that and both dispatchers correctly found nothing to
    claim. A test for concurrency cannot borrow a transaction that is designed
    never to commit.
    """
    from sqlalchemy.orm import sessionmaker
    Maker = sessionmaker(bind=platform_engine, expire_on_commit=False)

    setup = Maker()
    try:
        onboarding.onboard(setup, ids.partner_a, CSV)
        setup.commit()
    finally:
        setup.close()

    a, b = Maker(), Maker()
    try:
        cap_a, cap_b = OutboxEmailSender(), OutboxEmailSender()
        res_a = outbox.dispatch_pending(a, cap_a)      # claims and holds
        res_b = outbox.dispatch_pending(b, cap_b)      # must skip those rows
        a.commit(); b.commit()

        assert len(cap_a.sent) + len(cap_b.sent) == 2, (
            "both dispatchers found nothing -- the events were never committed")
        overlap = set(res_a.sent) & set(res_b.sent)
        assert not overlap, f"same event dispatched twice: {overlap}"
    finally:
        a.close(); b.close()
        with platform_engine.connect() as c:
            c.execute(text("DELETE FROM users WHERE email LIKE 'ob%@x.test'"))
            c.commit()


def _peek_tokens(db):
    """Decrypt the queued tokens, for tests that need to assert they do NOT
    appear somewhere. Uses the same AAD the dispatcher would."""
    from app.services.outbox_crypto import decrypt_token
    out = []
    for r in db.execute(text(
        "SELECT id, partner_id, invitation_id, event_type, recipient, "
        "token_ciphertext, token_nonce, key_version FROM outbox_events")).all():
        aad = build_aad(event_id=r.id, invitation_id=r.invitation_id,
                        partner_id=r.partner_id, event_type=r.event_type)
        out.append((r.recipient,
                    decrypt_token(r.token_ciphertext, r.token_nonce, aad, r.key_version)))
    return out
