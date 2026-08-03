"""What the dispatcher will and will not send, and what it locks to find out.

"Due" and "still worth sending" are different questions, and the claim used to
ask only the first: status pending, available_at reached. Both facts live on the
event, and neither says anything about whether the invitation it exists to
deliver is still real. Reported live: an expired invitation was mailed, and the
recipient received a token that could never be redeemed.

Most of this file runs in one rolled-back transaction on the platform path,
which is where dispatch actually runs today. The last test commits, and says
why.
"""
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.services import outbox
from app.services.email import OutboxEmailSender

DOMAIN = "claim.test"


def _queued(db, partner_id, *, status="pending", expires="7 days",
            accepted=False):
    """An invited user, an invitation in the requested state, and its queued
    mail -- enqueued through the real path so the ciphertext authenticates.

    The invitation's state is a parameter because that is the axis under test.
    Everything else is held constant.
    """
    uid, inv_id = uuid.uuid4(), uuid.uuid4()
    token = f"token-{uuid.uuid4().hex}"
    email = f"invitee-{uuid.uuid4().hex[:8]}@{DOMAIN}"

    db.execute(text(
        "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
        "VALUES (:u, :e, :p, 'partner', false)"),
        {"u": str(uid), "e": email, "p": str(partner_id)})
    db.execute(text(
        "INSERT INTO invitations (id, partner_id, user_id, email, token_hash, "
        "status, expires_at, accepted_at) VALUES "
        "(:i, :p, :u, :e, :h, :st, now() + make_interval(secs => :secs), :acc)"),
        {"i": str(inv_id), "p": str(partner_id), "u": str(uid), "e": email,
         "h": f"{uuid.uuid4().hex}{uuid.uuid4().hex}", "st": status,
         "secs": -3600 if expires == "past" else 7 * 86400,
         "acc": "now()" if accepted else None})
    if accepted:
        db.execute(text("UPDATE invitations SET accepted_at = now() WHERE id = :i"),
                   {"i": str(inv_id)})

    event_id = outbox.enqueue_invitation(
        db, partner_id=partner_id, invitation_id=inv_id,
        recipient=email, token=token)
    return SimpleNamespace(event_id=event_id, invitation_id=inv_id,
                           user_id=uid, email=email, token=token)


def _event(db, event_id):
    return db.execute(text(
        "SELECT status, token_ciphertext, token_nonce, last_error, attempts "
        "FROM outbox_events WHERE id = :v"), {"v": str(event_id)}).one()


def _set_partner_status(db, partner_id, status):
    """Raw status write, NOT suspend_partner().

    suspend_partner revokes the partner's pending invitations, which is correct
    behaviour and exactly what would make these tests unable to distinguish the
    two facts. Here the invitation must stay pending while the partner is not,
    so the two questions can be asked separately.
    """
    db.execute(text("UPDATE partners SET status = :s WHERE id = :p"),
               {"s": status, "p": str(partner_id)})


# --- the anchor -------------------------------------------------------------

def test_a_live_invitation_is_still_dispatched(ids, platform_orm):
    """Positive control for the whole file.

    Every test below asserts that something is NOT sent, and all of them pass
    for free if the new join matches nothing at all -- which is the single most
    likely way to get this wrong, since the join reaches across two tables and
    calls a function that returns false when it cannot read.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a)
        sender = OutboxEmailSender()
        result = outbox.dispatch_pending(db, sender)

        assert result.sent == [q.event_id]
        assert sender.sent == [(q.email, q.token)]


# --- irreversible: terminate ------------------------------------------------

def test_an_expired_invitation_is_terminated_not_sent(ids, platform_orm):
    """The reported bug. The recipient was getting a token that could not be
    redeemed -- an email that can only confuse, carrying a credential whose only
    remaining property is being a secret worth stealing.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a, expires="past")
        sender = OutboxEmailSender()
        result = outbox.dispatch_pending(db, sender)

        assert sender.sent == []
        assert result.sent == [] and result.terminated == [q.event_id]

        ev = _event(db, q.event_id)
        assert ev.status == "failed"
        assert ev.token_ciphertext is None and ev.token_nonce is None
        assert ev.last_error == "invitation expired"


def test_a_revoked_invitation_is_terminated_not_sent(ids, platform_orm):
    """0015 revokes pending invitations on suspension and domain deactivation.
    Without this the event stayed pending with its ciphertext, and the
    dispatcher -- which never consulted invitations -- would have mailed the
    token for an invitation that had been withdrawn.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a, status="revoked")
        result = outbox.dispatch_pending(db, OutboxEmailSender())

        assert result.terminated == [q.event_id]
        ev = _event(db, q.event_id)
        assert ev.status == "failed" and ev.token_ciphertext is None
        assert ev.last_error == "invitation revoked"


def test_an_accepted_invitation_is_terminated_not_sent(ids, platform_orm):
    """Redemption already happened, so the mail has no addressee left in any
    meaningful sense -- and a second copy of a one-time token is exactly the
    kind of thing at-least-once delivery is not supposed to mean.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a, status="accepted", accepted=True)
        result = outbox.dispatch_pending(db, OutboxEmailSender())

        assert result.terminated == [q.event_id]
        assert _event(db, q.event_id).last_error == "invitation accepted"


# --- reversible: hold, do not terminate -------------------------------------

def test_a_suspended_partners_event_is_held_not_terminated(ids, platform_orm):
    """The distinction this file exists to draw.

    Suspension makes an event undeliverable NOW; it does not make it
    undeliverable FOREVER, and clearing the ciphertext is not undoable --
    reactivating the partner could not bring the token back. So the event stays
    pending and simply goes unclaimed.

    Its payload is still bounded: the invitation expires on its own schedule,
    and the expiry branch collects it then.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a)
        _set_partner_status(db, ids.partner_a, "suspended")

        sender = OutboxEmailSender()
        result = outbox.dispatch_pending(db, sender)

        assert sender.sent == []
        assert result.total == 0, "a suspended partner's mail must not be terminated"

        ev = _event(db, q.event_id)
        assert ev.status == "pending"
        assert ev.token_ciphertext is not None and ev.token_nonce is not None
        assert ev.attempts == 0, "holding is not an attempt"


def test_reactivation_makes_a_held_event_deliverable_again(ids, platform_orm):
    """The other half of the same claim. Held-not-terminated is only the right
    call if the mail actually goes out afterwards; if it did not, terminating
    would have been the honest choice and this design would be strictly worse.
    """
    with platform_orm() as db:
        q = _queued(db, ids.partner_a)
        _set_partner_status(db, ids.partner_a, "suspended")
        assert outbox.dispatch_pending(db, OutboxEmailSender()).total == 0

        _set_partner_status(db, ids.partner_a, "active")
        sender = OutboxEmailSender()
        result = outbox.dispatch_pending(db, sender)

        assert result.sent == [q.event_id]
        assert sender.sent == [(q.email, q.token)]


# --- what the claim locks ---------------------------------------------------

def test_the_claim_locks_the_event_and_not_the_invitation(ids, platform_engine):
    """`FOR UPDATE OF o` versus a bare `FOR UPDATE`, which is a two-word
    difference with no visible effect on any assertion above.

    A bare FOR UPDATE locks the matching row in EVERY table of the join. The
    dispatcher would then hold row locks on invitations for the duration of an
    SMTP call, blocking redemptions -- and, because the claim uses SKIP LOCKED,
    would silently decline to send mail for any invitation a redemption was
    touching. Nothing about the outcome of a single-threaded test would change.

    So it is asserted as a pair: the event MUST be locked (or the claim did
    nothing and the second half proves nothing), and the invitation MUST NOT be.
    This test commits, because a lock held by one transaction is only observable
    from another.
    """
    Maker = sessionmaker(bind=platform_engine, expire_on_commit=False)
    setup = Maker()
    q = _queued(setup, ids.partner_a)
    setup.commit()
    setup.close()

    holder = Maker()
    try:
        claimed = holder.execute(text("SELECT 1")).scalar_one()  # open the tx
        assert claimed == 1
        rows = outbox._claim(holder, 100)
        assert any(r.id == q.event_id for r in rows), (
            "the claim did not take the event; the lock assertions below would "
            "pass for the wrong reason")

        with platform_engine.connect() as probe:
            with pytest.raises(DBAPIError) as exc:
                probe.execute(text(
                    "SELECT 1 FROM outbox_events WHERE id = :v FOR UPDATE NOWAIT"),
                    {"v": str(q.event_id)})
            probe.rollback()
        orig = exc.value.orig
        sqlstate = (getattr(orig, "sqlstate", None)
                    or getattr(getattr(orig, "diag", None), "sqlstate", None))
        assert sqlstate == "55P03", (
            f"expected lock_not_available on the claimed event, got {sqlstate}")

        with platform_engine.connect() as probe:
            probe.execute(text(
                "SELECT 1 FROM invitations WHERE id = :i FOR UPDATE NOWAIT"),
                {"i": str(q.invitation_id)})
            probe.rollback()
    finally:
        holder.rollback()
        holder.close()
        with platform_engine.connect() as c:
            c.execute(text("DELETE FROM outbox_events WHERE id = :v"),
                      {"v": str(q.event_id)})
            c.execute(text("DELETE FROM invitations WHERE id = :i"),
                      {"i": str(q.invitation_id)})
            c.execute(text("DELETE FROM users WHERE id = :u"), {"u": str(q.user_id)})
            c.commit()
