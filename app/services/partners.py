"""Partner lifecycle: activation / suspension / domain deactivation.

Suspension and domain deactivation each pair a state change with token
revocation, done in the SAME transaction so a partner can never be left
suspended-but-still-logged-in. Suspension is a platform / parent-hub capability
and runs on the platform path.
"""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.auth.sessions import revoke_partner_sessions, revoke_user_sessions
from app.services.activity import record
from app.models.partner import Partner
from app.models.enums import PartnerStatus

SUSPENSION_RETENTION = timedelta(days=60)  # JD: 60-day suspension retention

# The platform tenant (0009). It is a real partners row so that platform
# administrators and direct customers have something to FK to -- it is not a
# customer, and the partner lifecycle does not apply to it.
NIL = UUID("00000000-0000-0000-0000-000000000000")


def _lock_partner(db: OrmSession, partner_id: UUID) -> None:
    """Take a row lock on the partner for the rest of this transaction.

    Every lifecycle transition (suspend, activate, purge) goes through here, so
    they contend on one lock and cannot interleave. This is the piece that makes
    "who wins" a decided question rather than a race: the loser blocks, then
    sees the winner's committed state."""
    db.execute(text("SELECT 1 FROM partners WHERE id = :pid FOR UPDATE"),
               {"pid": str(partner_id)})


# Written into the terminated event so an operator reading the outbox can tell
# a lifecycle revocation apart from a delivery failure. Deliberately says
# nothing about the recipient or the token.
REVOKED_BY_LIFECYCLE = "invitation revoked by a partner lifecycle change"


def _revoke_pending_invitations(db: OrmSession, partner_id: UUID,
                                domain: str | None = None) -> tuple[int, int]:
    """Revoke pending invitations and terminate the mail queued for them.

    Both halves, in the caller's transaction. Revoking the invitation alone
    leaves a pending outbox row still holding recoverable ciphertext, and the
    dispatcher does not consult invitations -- so the token for an invitation
    that no longer exists would still go out. Fixing one side and not the other
    is the shape of half-fix this schema keeps getting audited for.

    The secret material is cleared rather than retained with a failed status:
    a dead token that is still decryptable is a liability with no remaining
    purpose.

    domain=None means every pending invitation in the partner (suspension). A
    domain narrows it to the users on that domain (domain deactivation).

    The narrowing is a SUBQUERY, not a list of user ids computed by the caller.
    Same rows either way; the difference is WHEN the caller may read `users`.
    With a precomputed list the caller had to scan users BEFORE this statement,
    and this statement is the one that blocks on a concurrent redemption -- so
    the scan happened on the pre-block snapshot and could not see a user the
    redemption activated while we waited. Keeping the user lookup inside the
    blocking statement leaves the caller free to scan afterwards.

    An empty match revokes nothing, which falls out of the subquery instead of
    needing the caller to distinguish an empty list from None.
    """
    params: dict = {"pid": str(partner_id)}
    narrowing = ""
    if domain is not None:
        narrowing = (" AND user_id IN (SELECT id FROM users "
                     " WHERE partner_id = :pid "
                     "   AND split_part(lower(email), '@', 2) = :domain)")
        params["domain"] = domain

    revoked = db.execute(text(
        "UPDATE invitations SET status = 'revoked' "
        "WHERE partner_id = :pid AND status = 'pending'" + narrowing +
        " RETURNING id"), params).all()
    if not revoked:
        return 0, 0

    terminated = db.execute(text(
        "UPDATE outbox_events SET status = 'failed', last_error = :err, "
        "  token_ciphertext = NULL, token_nonce = NULL "
        "WHERE partner_id = :pid AND status = 'pending' "
        "  AND invitation_id = ANY(CAST(:inv AS uuid[]))"),
        {"pid": str(partner_id), "err": REVOKED_BY_LIFECYCLE,
         "inv": [str(r.id) for r in revoked]}).rowcount
    return len(revoked), terminated


def suspend_partner(db: OrmSession, partner_id: UUID) -> int:
    """Suspend a partner, stamp the 60-day retention window, and revoke every
    live session across the partner. Returns the number of sessions revoked."""
    if partner_id == NIL:
        raise ValueError("the platform tenant cannot be suspended")
    now = datetime.now(timezone.utc)
    # Lock the row for the whole transition. suspend / activate / purge all
    # contend for this same lock, so they serialise: whoever takes it first
    # decides, and the others observe the committed result instead of acting on
    # a stale read. Without it, activate and purge could both believe they had
    # seen a suspended partner.
    _lock_partner(db, partner_id)
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.suspended
    partner.suspended_at = now
    partner.suspension_retention_until = now + SUSPENSION_RETENTION
    db.flush()  # persist the state change within the transaction
    revoked = revoke_partner_sessions(db, partner_id)
    # A pending invitation is a credential that has not been picked up yet.
    # Revoking live sessions while leaving those outstanding means suspension
    # only stops the users who already logged in.
    invites, events = _revoke_pending_invitations(db, partner_id)
    record(db, partner_id, "partner.suspended",
           payload={"sessions_revoked": revoked, "invitations_revoked": invites,
                    "outbox_events_terminated": events})
    return revoked


def activate_partner(db: OrmSession, partner_id: UUID) -> None:
    """Reactivate a partner and clear the suspension window."""
    if partner_id == NIL:
        raise ValueError("the platform tenant has no lifecycle to activate")
    _lock_partner(db, partner_id)
    partner = db.get(Partner, partner_id)
    if partner is None:
        raise ValueError(f"partner {partner_id} not found")
    partner.status = PartnerStatus.active
    partner.suspended_at = None
    partner.suspension_retention_until = None
    db.flush()
    record(db, partner_id, "partner.activated")


def deactivate_domain(db: OrmSession, partner_id: UUID, domain: str) -> int:
    """Deactivate all of a partner's users on an email domain, revoke their
    sessions, and revoke any invitation still outstanding for them. Scoped to
    one partner by the explicit partner_id predicate. Returns the number of
    users flipped from active to inactive.

    `is_active = false` is not a marker of "already dealt with". An invited user
    is inactive from the moment they are created until they redeem, so the
    previous version's `AND is_active = true` filter skipped exactly the users
    whose access was still pending -- and their token stayed live. Reported
    live: deactivating a domain reported 0 users affected, and the pending
    invitee then redeemed and activated themselves.

    So the scan covers every user on the domain, and what varies per user is
    only whether there was an active flag to clear.
    """
    if partner_id == NIL:
        # suspend_partner and activate_partner have refused the platform tenant
        # since 0009; this path did not, and deactivating a domain on the NIL
        # tenant took out direct customers who have no partner lifecycle at all.
        # The forbidden side of a rule has to be written everywhere the rule is
        # enforced, not once.
        raise ValueError("the platform tenant cannot be domain-deactivated")

    # Same lock suspend and activate take, so the lifecycle transitions
    # serialise among themselves.
    #
    # It is NOT what orders this against a concurrent redemption. That is
    # settled by the invitation revocation below: accept_invitation claims on
    # `status = 'pending'`, so whichever of the two commits first, the other
    # re-reads that column on the row it is already locking and steps aside.
    # accept_invitation deliberately takes no lock on partners -- SELECT FOR
    # SHARE requires UPDATE privilege there, which the runtime role no longer
    # has since 0015.
    #
    # That predicate is symmetric. The CONSEQUENCE of losing is not, and the
    # earlier version of this function read the symmetry as safety. A redemption
    # that steps aside refuses to redeem, which is the safe outcome. A domain
    # deactivation that steps aside abandons the deactivation, which is not --
    # it returned success having done nothing, while the user it was supposed to
    # disable finished redeeming and stayed active. Reported live: the reverse
    # order (redemption claims first, deactivation arrives second) left
    # `('accepted', is_active=True)` and an affected count of 0.
    #
    # The two racers are not interchangeable, so the ordering below is not
    # either. Suspension does not have this problem because it writes a durable
    # fact -- partners.status -- that accept_invitation reads as a conjunct via
    # partner_is_active(). A deactivated domain is not a fact anywhere: there is
    # no domain entity, no column, no row. It is a scan-and-assign over `users`,
    # so a redemption arriving afterwards has nothing to consult. Closing THAT
    # needs an entity and is out of scope here; what follows closes the race.
    _lock_partner(db, partner_id)

    # Exact comparison on the parsed domain, not a LIKE pattern. The domain was
    # interpolated into `LIKE '%@' || domain`, so a caller passing '%' produced
    # '%@%' and deactivated every active user in the partner. Escaping the
    # wildcards would work and would leave the next author responsible for
    # remembering to escape; splitting the address removes pattern semantics
    # from the query altogether, so there is nothing left to forget.
    normalized = domain.lower().lstrip("@")

    # Revoke FIRST. This statement is the serialisation point: a redemption
    # holding the invitation row makes it wait, and it re-reads `status` on that
    # row when it unblocks. Everything after this line therefore reads a
    # database in which the concurrent redemption has already committed or has
    # already been refused -- there is no third state left.
    _revoke_pending_invitations(db, partner_id, domain=normalized)

    # Scan SECOND, on the far side of that wait. This is the whole fix: the
    # previous order read `is_active` before blocking, saw the pre-redemption
    # false, skipped the user, and then discovered the invitation was no longer
    # pending -- so neither half acted on the user who had just been activated.
    rows = db.execute(
        text("SELECT id, is_active FROM users "
             "WHERE partner_id = :pid AND split_part(lower(email), '@', 2) = :domain"),
        {"pid": str(partner_id), "domain": normalized},
    ).all()

    deactivated = 0
    for row in rows:
        if row.is_active:
            db.execute(text("UPDATE users SET is_active = false WHERE id = :id"),
                       {"id": str(row.id)})
            deactivated += 1
        revoke_user_sessions(db, row.id)

    return deactivated


def get_billing_contact(db: OrmSession, partner_id: UUID) -> str | None:
    return db.execute(
        text("SELECT billing_contact_email FROM partners WHERE id = :p"),
        {"p": str(partner_id)}).scalar_one_or_none()


def set_billing_contact(db: OrmSession, email: str | None) -> int:
    """Set the calling tenant's billing contact through the 0015 function.

    NO partner_id parameter, and the omission is the point. 0015's function
    reads the tenant from the transaction GUC, so an argument here would be
    accepted and ignored. The first version of this wrapper kept one: called
    while scoped to partner A with partner B's id, it wrote A's row and
    returned success -- worse than the naked UPDATE it replaced, which at least
    touched nothing. That is precisely the failure 0015's own docstring argues
    against for the SQL function, reproduced one layer up because the layer was
    not re-read with the same rule in hand.

    Returns 1 if the row was updated, 0 if the database refused -- which today
    means the partner is not active, or no tenant scope is set. Callers map 0 to
    403 rather than reporting a successful write, because "0 rows" is what a
    blocked write looks like and it is indistinguishable from success to
    anything that only checks for an exception.
    """
    ok = db.execute(
        text("SELECT public.set_active_partner_billing_contact(CAST(:e AS text))"),
        {"e": email}).scalar_one()
    if not ok:
        return 0
    # Reached only when the function returned true, which means the GUC already
    # parsed to a real, active tenant inside it. This read therefore does not
    # need 0004's NULLIF hardening -- it is unreachable unless the hardened
    # version succeeded first -- so it is not a seventh copy of that expression.
    tenant = db.execute(
        text("SELECT current_setting('app.partner_id')::uuid")).scalar_one()
    record(db, tenant, "partner.billing_contact_updated", payload={"email": email})
    return 1
