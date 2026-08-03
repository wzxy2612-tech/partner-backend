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
from app.services.outbox_crypto import (OutboxCryptoError, build_aad,
                                        decrypt_token, encrypt_token)

EVENT_INVITATION_CREATED = "invitation.created"

MAX_ATTEMPTS = 5
# Exponential backoff, capped. Index is the attempt count already made.
BACKOFF = [timedelta(seconds=s) for s in (0, 30, 300, 1800, 7200)]


@dataclass
class DispatchResult:
    sent: list[UUID] = field(default_factory=list)
    retried: list[UUID] = field(default_factory=list)
    dead_lettered: list[UUID] = field(default_factory=list)
    # Events whose invitation died before the mail went out. Counted in total
    # because "nothing happened" is false when rows were terminated, and a
    # caller checking total == 0 to decide whether to log anything would
    # otherwise miss a batch of them.
    terminated: list[UUID] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (len(self.sent) + len(self.retried) + len(self.dead_lettered)
                + len(self.terminated))


def enqueue_invitation(db: OrmSession, *, partner_id: UUID, invitation_id: UUID,
                       recipient: str, token: str) -> UUID:
    """Record the intent to mail an invitation, in the CALLER'S transaction.

    Must be called inside the same transaction that created the invitation --
    that is the entire mechanism. If the batch rolls back, this row goes with
    it and nothing is ever sent.

    The row id is generated here rather than by the database default, because
    the AAD binds the ciphertext to that id and it therefore has to be known
    before the ciphertext is computed.

    `status` and `available_at` are deliberately not named. Both carry server
    defaults ('pending', now()), and 0019 does not grant the runtime role INSERT
    on either column -- so a tenant cannot express a non-pending or future-dated
    event at all. Not "is rejected if it tries": there is no column for it to
    write through. Restating the defaults here would work today and would make
    the grant look wider than it is to whoever reads this next.
    """
    from uuid import uuid4
    event_id = uuid4()
    aad = build_aad(event_id=event_id, invitation_id=invitation_id,
                    partner_id=partner_id, event_type=EVENT_INVITATION_CREATED)
    # The version comes back FROM the encryption rather than being looked up
    # again here. Two lookups agreed only while it was a constant; once it
    # became configuration, a row recording a version it was not encrypted
    # under would go unnoticed until a dispatcher failed to decrypt it.
    ciphertext, nonce, key_version = encrypt_token(token, aad)

    db.execute(text(
        "INSERT INTO outbox_events "
        "(id, partner_id, invitation_id, event_type, recipient, "
        " token_ciphertext, token_nonce, key_version) "
        "VALUES (:id, :pid, :inv, :et, :rcpt, :ct, :nonce, :kv)"),
        {"id": str(event_id), "pid": str(partner_id), "inv": str(invitation_id),
         "et": EVENT_INVITATION_CREATED, "rcpt": recipient,
         "ct": ciphertext, "nonce": nonce, "kv": key_version})
    return event_id


def _claim(db: OrmSession, limit: int) -> list:
    """Take a batch of DELIVERABLE events, locked so a second dispatcher takes
    others.

    "Due" is not the same as "still worth sending", and this query used to ask
    only the first question -- status pending, available_at reached -- which is
    entirely about the event and says nothing about whether the thing it exists
    to deliver is still real. Reported live: an expired invitation was mailed,
    and the recipient got a token that could never be redeemed.

    Two facts are joined in, neither of them a fresh copy of a rule stated
    elsewhere:

      * the invitation is still pending and unexpired. The invitations table is
        the single adjudicator of that, and 0015 made the lifecycle transitions
        write revocation there rather than leaving it to be inferred.
      * the partner may act -- partner_is_active(), the same function twelve
        policies call. NOT `p.status = 'active'` spelled out again here: this
        path runs BYPASSRLS, which makes it exactly the kind of place a second
        copy of the predicate drifts unnoticed.

    FOR UPDATE **OF o**, not a bare FOR UPDATE. Without the OF clause PostgreSQL
    locks the matching row in every table of the join, so the dispatcher would
    take row locks on invitations -- contending with accept_invitation for them,
    and, with SKIP LOCKED, silently declining to send mail for any invitation a
    redemption happened to be touching. The dispatcher has no business locking a
    row it only reads.

    SKIP LOCKED is what makes concurrent dispatchers safe: the second steps over
    rows the first is holding instead of blocking on them or -- far worse --
    reading them and sending the same mail twice.
    """
    return db.execute(text(
        "SELECT o.id, o.partner_id, o.invitation_id, o.event_type, o.recipient, "
        "       o.token_ciphertext, o.token_nonce, o.key_version, o.attempts "
        "FROM outbox_events o "
        "JOIN invitations i "
        "  ON i.id = o.invitation_id AND i.partner_id = o.partner_id "
        "WHERE o.status = 'pending' AND o.available_at <= now() "
        "  AND i.status = 'pending' AND i.expires_at > now() "
        "  AND public.partner_is_active(o.partner_id) "
        "ORDER BY o.available_at "
        "LIMIT :lim "
        "FOR UPDATE OF o SKIP LOCKED"), {"lim": limit}).all()


def _reap_undeliverable(db: OrmSession, limit: int) -> list:
    """Move events whose invitation died to a terminal state, secret cleared.

    Without this they stay pending forever: invisible to the claim above, still
    holding recoverable ciphertext, and indistinguishable from a backlog.

    ONLY IRREVERSIBLE CONDITIONS TERMINATE. accepted, revoked and expired are
    all one-way, so an event whose invitation is in one of those states can
    never become deliverable again and its payload is pure liability.

    A suspended partner is NOT one of them, and that is a deliberate departure
    from treating "not currently deliverable" and "never deliverable" as the
    same question. Suspension can be lifted. Terminating on it would destroy
    deliverable mail on a condition that may not hold tomorrow, and clearing the
    ciphertext is not undoable -- reactivating the partner could not bring the
    token back. Those events stay pending and simply go unclaimed for the
    duration; their ciphertext is still bounded, because the invitation expires
    on its own schedule and the expiry branch here collects it then.

    The irreversible half is already recorded where it belongs: 0015 made
    suspension and domain deactivation revoke the invitations they invalidate.
    This reads that decision instead of making a second one about the same fact.
    """
    return db.execute(text(
        "WITH doomed AS ("
        "  SELECT o.id, "
        "         CASE WHEN i.status <> 'pending' "
        "              THEN 'invitation ' || i.status "
        "              ELSE 'invitation expired' END AS reason "
        "  FROM outbox_events o "
        "  JOIN invitations i "
        "    ON i.id = o.invitation_id AND i.partner_id = o.partner_id "
        "  WHERE o.status = 'pending' "
        "    AND (i.status <> 'pending' OR i.expires_at <= now()) "
        "  ORDER BY o.id "
        "  LIMIT :lim "
        "  FOR UPDATE OF o SKIP LOCKED"
        ") "
        "UPDATE outbox_events e "
        "   SET status = 'failed', last_error = d.reason, "
        "       token_ciphertext = NULL, token_nonce = NULL "
        "  FROM doomed d "
        " WHERE e.id = d.id "
        "RETURNING e.id"), {"lim": limit}).scalars().all()


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

    # Reap first, so a batch is not spent decrypting events that are already
    # dead. The claim re-checks the same conditions independently rather than
    # trusting this to have caught everything: a redemption can commit between
    # the two statements, and this one stops at `limit`.
    result.terminated.extend(_reap_undeliverable(db, limit))

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
