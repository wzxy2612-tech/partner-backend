"""Transactional outbox: record the intent to send inside the transaction,
deliver after it commits.

provision() used to call the mailer inside the batch SAVEPOINT. A failure on a
later row rolled back every user and invitation -- and left the earlier
recipients holding tokens for records that no longer existed. An external side
effect cannot participate in a rollback, so it must not happen until the
transaction that justifies it has committed.

enqueue_invitation() writes the event in the caller's transaction, so the
invitation and the intent to mail it are atomic together: either both exist or
neither does. dispatch_pending() runs afterwards and only ever sees committed
rows.

DELIVERY IS AT-LEAST-ONCE. A provider can accept a message and still fail to
return a response, so a retry can duplicate the mail. That is the honest
guarantee, and it is safe here because redemption is a single conditional UPDATE
(one atomic claim): a duplicate invitation email cannot produce a second
account. Exactly-once delivery to a third party is not achievable and claiming
it would be worse than not having it.

This module deliberately stops at a callable dispatcher. There is no daemon, no
queue and no scheduler: those are deployment topology, and inventing them here
would grow the surface without adding anything to the reliability argument. A
cron job, a queue consumer or a scheduled container task calls dispatch_pending()
and gets the same semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.services.email import EmailSender
from app.services.outbox_crypto import (CURRENT_KEY_VERSION, OutboxCryptoError,
                                        build_aad, decrypt_token, encrypt_token)

EVENT_INVITATION_CREATED = "invitation.created"

MAX_ATTEMPTS = 5
# Exponential backoff, capped. Index is the attempt count already made.
BACKOFF = [timedelta(seconds=s) for s in (0, 30, 300, 1800, 7200)]


@dataclass
class DispatchResult:
    sent: list[UUID] = field(default_factory=list)
    retried: list[UUID] = field(default_factory=list)
    dead_lettered: list[UUID] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.sent) + len(self.retried) + len(self.dead_lettered)


def enqueue_invitation(db: OrmSession, *, partner_id: UUID, invitation_id: UUID,
                       recipient: str, token: str) -> UUID:
    """Record the intent to mail an invitation, in the CALLER'S transaction.

    Must be called inside the same transaction that created the invitation --
    that is the entire mechanism. If the batch rolls back, this row goes with
    it and nothing is ever sent.

    The row id is generated here rather than by the database default, because
    the AAD binds the ciphertext to that id and it therefore has to be known
    before the ciphertext is computed.
    """
    from uuid import uuid4
    event_id = uuid4()
    aad = build_aad(event_id=event_id, invitation_id=invitation_id,
                    partner_id=partner_id, event_type=EVENT_INVITATION_CREATED)
    ciphertext, nonce = encrypt_token(token, aad)

    db.execute(text(
        "INSERT INTO outbox_events "
        "(id, partner_id, invitation_id, event_type, recipient, "
        " token_ciphertext, token_nonce, key_version, status, available_at) "
        "VALUES (:id, :pid, :inv, :et, :rcpt, :ct, :nonce, :kv, 'pending', now())"),
        {"id": str(event_id), "pid": str(partner_id), "inv": str(invitation_id),
         "et": EVENT_INVITATION_CREATED, "rcpt": recipient,
         "ct": ciphertext, "nonce": nonce, "kv": CURRENT_KEY_VERSION})
    return event_id


def _claim(db: OrmSession, limit: int) -> list:
    """Take a batch of due events, locked so a second dispatcher takes others.

    FOR UPDATE SKIP LOCKED is what makes concurrent dispatchers safe: the second
    one steps over rows the first is holding instead of blocking on them or --
    far worse -- reading them and sending the same mail twice.
    """
    return db.execute(text(
        "SELECT id, partner_id, invitation_id, event_type, recipient, "
        "       token_ciphertext, token_nonce, key_version, attempts "
        "FROM outbox_events "
        "WHERE status = 'pending' AND available_at <= now() "
        "ORDER BY available_at "
        "LIMIT :lim "
        "FOR UPDATE SKIP LOCKED"), {"lim": limit}).all()


def dispatch_pending(db: OrmSession, sender: EmailSender, *,
                     limit: int = 100) -> DispatchResult:
    """Deliver due events. Call AFTER the business transaction has committed.

    Each event is decrypted, sent, and then either marked sent (with its secret
    material cleared in the same statement) or scheduled for a retry. Reaching
    MAX_ATTEMPTS moves it to `failed`, which is the dead-letter state: it stops
    being retried and stays for inspection, rather than disappearing or
    retrying forever.
    """
    result = DispatchResult()

    for row in _claim(db, limit):
        aad = build_aad(event_id=row.id, invitation_id=row.invitation_id,
                        partner_id=row.partner_id, event_type=row.event_type)
        try:
            token = decrypt_token(row.token_ciphertext, row.token_nonce, aad,
                                  row.key_version)
        except OutboxCryptoError:
            # Unauthenticated payload: a ciphertext that does not belong to this
            # row, or a key that is gone. Retrying cannot fix either, so it goes
            # straight to dead-letter instead of burning attempts.
            _dead_letter(db, row.id, "payload failed authentication")
            result.dead_lettered.append(row.id)
            continue

        try:
            sender.send_invitation(row.recipient, token)
        except Exception as exc:
            # Never interpolate the token or the payload into the stored error.
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
            if row.attempts + 1 >= MAX_ATTEMPTS:
                _dead_letter(db, row.id, reason)
                result.dead_lettered.append(row.id)
            else:
                _schedule_retry(db, row.id, row.attempts + 1, reason)
                result.retried.append(row.id)
            continue

        # Success: the secret material is destroyed in the same statement that
        # records delivery, so there is no window where a sent row still carries
        # a redeemable token. 0013 enforces the pairing as a CHECK.
        db.execute(text(
            "UPDATE outbox_events SET status = 'sent', sent_at = now(), "
            "  attempts = attempts + 1, "
            "  token_ciphertext = NULL, token_nonce = NULL, last_error = NULL "
            "WHERE id = :id"), {"id": str(row.id)})
        result.sent.append(row.id)

    return result


def _schedule_retry(db: OrmSession, event_id: UUID, attempts: int,
                    reason: str) -> None:
    delay = BACKOFF[min(attempts, len(BACKOFF) - 1)]
    db.execute(text(
        "UPDATE outbox_events SET attempts = :n, last_error = :err, "
        "  available_at = now() + make_interval(secs => :secs) "
        "WHERE id = :id"),
        {"n": attempts, "err": reason, "secs": delay.total_seconds(),
         "id": str(event_id)})


def _dead_letter(db: OrmSession, event_id: UUID, reason: str) -> None:
    """Terminal. The payload is cleared here too -- a permanently undeliverable
    event has no reason to keep a redeemable token, and leaving one would make
    dead-letter rows the softest target in the table."""
    db.execute(text(
        "UPDATE outbox_events SET status = 'failed', attempts = attempts + 1, "
        "  last_error = :err, token_ciphertext = NULL, token_nonce = NULL "
        "WHERE id = :id"), {"err": reason, "id": str(event_id)})
