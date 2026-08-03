"""The outbox state machine, asserted at the database rather than trusted.

0013's only constraint was

    CHECK ((status = 'sent') = (token_ciphertext IS NULL AND sent_at IS NOT NULL))

which says nothing whatsoever about `failed` rows -- a dead-lettered event could
keep a fully recoverable invitation token, and only application code choosing to
clear it prevented that. `token_nonce` was not mentioned for any status.

Application code doing the right thing is not the same as the right thing being
enforced. Every clearing path here (_dead_letter, the success branch,
_reap_undeliverable, the 0015 lifecycle revocation) is correct today; 0017 makes
"correct today" into "cannot be otherwise", including for a hand-written UPDATE.

Each test names the constraint it expects via diag.constraint_name rather than
matching message text -- the same reason onboarding.py does.
"""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.services import outbox
from app.services.email import OutboxEmailSender


def _constraint(exc) -> str | None:
    orig = exc.value.orig
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


def _queued(db, partner_id):
    """One pending event through the real enqueue path."""
    uid, inv_id = uuid.uuid4(), uuid.uuid4()
    email = f"inv-{uuid.uuid4().hex[:8]}@invariant.test"
    db.execute(text(
        "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
        "VALUES (:u, :e, :p, 'partner', false)"),
        {"u": str(uid), "e": email, "p": str(partner_id)})
    db.execute(text(
        "INSERT INTO invitations (id, partner_id, user_id, email, token_hash, "
        "status, expires_at) VALUES "
        "(:i, :p, :u, :e, :h, 'pending', now() + interval '7 days')"),
        {"i": str(inv_id), "p": str(partner_id), "u": str(uid), "e": email,
         "h": f"{uuid.uuid4().hex}{uuid.uuid4().hex}"})
    event_id = outbox.enqueue_invitation(
        db, partner_id=partner_id, invitation_id=inv_id,
        recipient=email, token=f"token-{uuid.uuid4().hex}")
    return event_id, inv_id


# --- pending must be deliverable --------------------------------------------

def test_a_pending_event_must_carry_its_payload(ids, platform_orm):
    """A pending row with no ciphertext is an event that will be claimed
    forever and can never be delivered -- a backlog entry that is not work.
    """
    with platform_orm() as db:
        event_id, _ = _queued(db, ids.partner_a)
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(
                "UPDATE outbox_events SET token_ciphertext = NULL WHERE id = :v"),
                {"v": str(event_id)})
    assert _constraint(exc) == "ck_outbox_pending_has_payload"


def test_a_pending_event_may_not_claim_delivery(ids, platform_orm):
    """sent_at on a pending row means two parts of the same record disagree
    about whether the mail went out.
    """
    with platform_orm() as db:
        event_id, _ = _queued(db, ids.partner_a)
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(
                "UPDATE outbox_events SET sent_at = now() WHERE id = :v"),
                {"v": str(event_id)})
    assert _constraint(exc) == "ck_outbox_pending_has_payload"


# --- terminal must be clean -------------------------------------------------

def test_a_sent_event_may_not_keep_the_ciphertext(ids, platform_orm):
    """0013 already enforced this half. It is asserted here anyway so the three
    constraints are pinned as a set -- replacing one and quietly weakening
    another is exactly the shape this migration was written to close.
    """
    with platform_orm() as db:
        event_id, _ = _queued(db, ids.partner_a)
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(
                "UPDATE outbox_events SET status = 'sent', sent_at = now() "
                "WHERE id = :v"), {"v": str(event_id)})
    assert _constraint(exc) == "ck_outbox_sent_is_clean"


def test_a_failed_event_may_not_keep_the_ciphertext(ids, platform_orm):
    """The reported defect. Under 0013 this UPDATE succeeded, and the row sat in
    a terminal state holding a redeemable invitation token indefinitely.
    """
    with platform_orm() as db:
        event_id, _ = _queued(db, ids.partner_a)
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(
                "UPDATE outbox_events SET status = 'failed' WHERE id = :v"),
                {"v": str(event_id)})
    assert _constraint(exc) == "ck_outbox_failed_is_clean"


def test_a_failed_event_may_not_keep_the_nonce_either(ids, platform_orm):
    """token_nonce appeared in no constraint at all, for any status.

    A nonce alone is not a secret, so this is the smallest of the gaps -- and it
    is the one that shows the old constraint was written about a specific
    reported symptom rather than about the invariant. Half a payload left behind
    is a row whose columns no longer describe a state the code can produce.
    """
    with platform_orm() as db:
        event_id, _ = _queued(db, ids.partner_a)
        with pytest.raises(DBAPIError) as exc:
            db.execute(text(
                "UPDATE outbox_events SET status = 'failed', "
                "  token_ciphertext = NULL WHERE id = :v"),
                {"v": str(event_id)})
    assert _constraint(exc) == "ck_outbox_failed_is_clean"


# --- the real paths still fit ------------------------------------------------

def test_every_real_transition_produces_a_legal_row(ids, platform_orm):
    """The positive control, and the thing that would actually break users.

    Four constraints that reject everything would pass all four tests above. So
    the three transitions the code performs -- delivered, dead-lettered,
    reaped -- are driven end to end here; any of them landing in a state the
    invariants forbid raises inside the service rather than in a test fixture.
    """
    with platform_orm() as db:
        delivered, _ = _queued(db, ids.partner_a)
        reaped, reaped_inv = _queued(db, ids.partner_a)
        db.execute(text("UPDATE invitations SET status = 'revoked' WHERE id = :i"),
                   {"i": str(reaped_inv)})

        result = outbox.dispatch_pending(db, OutboxEmailSender())
        assert result.sent == [delivered]
        assert result.terminated == [reaped]

        dead, _ = _queued(db, ids.partner_a)
        outbox._dead_letter(db, dead, "provider refused")

        rows = db.execute(text(
            "SELECT id, status, token_ciphertext IS NULL AS clean_ct, "
            "       token_nonce IS NULL AS clean_nonce, sent_at "
            "FROM outbox_events WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(delivered), str(reaped), str(dead)]}).all()
        by_id = {r.id: r for r in rows}

        assert by_id[delivered].status == "sent"
        assert by_id[delivered].sent_at is not None
        assert by_id[reaped].status == "failed" and by_id[reaped].sent_at is None
        assert by_id[dead].status == "failed" and by_id[dead].sent_at is None
        assert all(r.clean_ct and r.clean_nonce for r in rows)
