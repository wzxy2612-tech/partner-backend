"""TOCTOU: stale requests, suspended logins, and the activate/purge race.

These use TWO REAL CONNECTIONS on purpose. Every other DB test in this suite
runs inside one rolled-back transaction, which is exactly the setup that cannot
observe a race: a single transaction never sees another's commit. To prove that
a suspend landing mid-request actually stops the request, one connection has to
commit while the other is still open.

That means these tests COMMIT, so each cleans up after itself rather than
relying on the fixture rollback. The partner used here is created per-test and
deleted at the end, so the shared seed is never mutated.

What each one pins:

  * stale principal vs suspend -- the audit's reproduction. A principal resolved
    before the suspend must not be able to write after it. The guarantee comes
    from the RLS policy (0011), not from a re-check in Python, so the test
    exercises the runtime path directly.
  * suspended login -- no new session may be minted during a suspension, so
    reactivation cannot silently revive a token created while suspended.
  * activate vs purge -- whoever takes the partner row lock first decides. Both
    succeeding is the failure this rules out.
  * suspend vs redemption, and domain-deactivate vs redemption -- these two
    OVERLAP the transactions rather than sequencing them. The activate/purge
    test above commits one side before the other starts, which pins the
    committed-order case but never makes anything block. accept_invitation
    takes no lock on partners (SELECT FOR SHARE needs UPDATE privilege there,
    which the runtime role lost in 0015), so what orders it against a lifecycle
    transition is the invitation's own status -- a column on the row the UPDATE
    already locks. That is a claim about PostgreSQL re-evaluating a qual when a
    conflicting transaction commits, and it was reasoning, not evidence, until
    these two.
"""
import threading
import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.auth.tokens import hash_token
from app.services.onboarding import accept_invitation
from app.services.partners import suspend_partner, deactivate_domain


@pytest.fixture()
def temp_partner(platform_engine):
    """A committed, disposable partner + user. Committed because these tests
    need a second connection to see it."""
    pid, uid = uuid.uuid4(), uuid.uuid4()
    with platform_engine.connect() as c:
        c.execute(text(
            "INSERT INTO partners (id, name, status) VALUES (:p, 'TOCTOU', 'active')"),
            {"p": str(pid)})
        c.execute(text(
            "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
            "VALUES (:u, :e, :p, 'partner', true)"),
            {"u": str(uid), "e": f"toctou-{uid}@t.test", "p": str(pid)})
        c.execute(text(
            "INSERT INTO companies (id, partner_id, name, branding) "
            "VALUES (:c, :p, 'C', '{}'::jsonb)"),
            {"c": str(uuid.uuid4()), "p": str(pid)})
        c.commit()
    yield pid, uid
    with platform_engine.connect() as c:
        c.execute(text("DELETE FROM users WHERE partner_id = :p"), {"p": str(pid)})
        c.execute(text("DELETE FROM partners WHERE id = :p"), {"p": str(pid)})
        c.commit()


def _suspend(engine, pid):
    """Suspend on its own connection and COMMIT, simulating the concurrent
    operator action that lands mid-request."""
    with engine.connect() as c:
        c.execute(text(
            "UPDATE partners SET status = 'suspended', suspended_at = now(), "
            "suspension_retention_until = now() + interval '60 days' WHERE id = :p"),
            {"p": str(pid)})
        c.commit()


# --- stale request vs suspend ----------------------------------------------

def test_runtime_writes_stop_the_moment_suspend_commits(temp_partner, platform_engine,
                                                        runtime_engine):
    """The audit's reproduction, inverted into a guarantee.

    Open a runtime (RLS) transaction as the partner -- the position an in-flight
    request holds after its principal was resolved. Suspend commits on another
    connection. The in-flight transaction's NEXT write must fail to insert,
    because the policy now requires the tenant to be active. No Python re-check
    is involved."""
    pid, _uid = temp_partner
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        # Before: a write inside the tenant succeeds.
        c.execute(text(
            "INSERT INTO companies (id, partner_id, name, branding) "
            "VALUES (:c, :p, 'before', '{}'::jsonb)"),
            {"c": str(uuid.uuid4()), "p": str(pid)})
        c.commit()

        _suspend(platform_engine, pid)

        # After: the same statement, same session, same scope -- refused by RLS.
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        with pytest.raises(Exception):
            c.execute(text(
                "INSERT INTO companies (id, partner_id, name, branding) "
                "VALUES (:c, :p, 'after', '{}'::jsonb)"),
                {"c": str(uuid.uuid4()), "p": str(pid)})
            c.commit()
        c.rollback()


def test_suspended_partner_reads_nothing_on_the_runtime_path(temp_partner,
                                                             platform_engine,
                                                             runtime_engine):
    """Reads collapse to zero rows too, so a stale request cannot even observe
    the tenant it was scoped to."""
    pid, _ = temp_partner
    _suspend(platform_engine, pid)
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        n = c.execute(text("SELECT count(*) FROM companies")).scalar_one()
        assert n == 0
        c.rollback()


def test_platform_path_still_works_while_suspended(temp_partner, platform_engine):
    """Required for the gate to be usable: the operator who has to un-suspend
    must still be able to see and act on the partner. app_platform is BYPASSRLS,
    so the gate does not apply to it."""
    pid, _ = temp_partner
    _suspend(platform_engine, pid)
    with platform_engine.connect() as c:
        row = c.execute(text("SELECT status FROM partners WHERE id = :p"),
                        {"p": str(pid)}).first()
        assert row is not None and row.status == "suspended"
        c.rollback()


def test_reactivation_restores_the_runtime_path(temp_partner, platform_engine,
                                                runtime_engine):
    """The gate must be reversible -- suspension is not deletion."""
    pid, _ = temp_partner
    _suspend(platform_engine, pid)
    with platform_engine.connect() as c:
        c.execute(text("UPDATE partners SET status = 'active', suspended_at = NULL, "
                       "suspension_retention_until = NULL WHERE id = :p"), {"p": str(pid)})
        c.commit()
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        assert c.execute(text("SELECT count(*) FROM companies")).scalar_one() >= 1
        c.rollback()



def test_suspended_tenant_cannot_reactivate_itself(temp_partner, platform_engine,
                                                   runtime_engine):
    """The hole that opened when the recursion fix ungated the partners policy.

    partners must keep an ungated `id = GUC` policy, because gating it makes the
    policy call a function that reads partners -- unbounded recursion. But an
    ungated policy checks only the id, and app_runtime held UPDATE on every table
    by default privilege, so a suspended tenant could set its own status back to
    'active' and walk out of the suspension -- reachable by exactly the in-flight
    request this round is about.

    Closed by revoking write on partners from the runtime role rather than by
    policy: the lifecycle is a platform-path concern."""
    pid, _ = temp_partner
    _suspend(platform_engine, pid)
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        with pytest.raises(Exception):
            c.execute(text("UPDATE partners SET status = 'active' WHERE id = :p"),
                      {"p": str(pid)})
            c.commit()
        c.rollback()
    with platform_engine.connect() as c:
        assert c.execute(text("SELECT status FROM partners WHERE id = :p"),
                         {"p": str(pid)}).scalar_one() == "suspended"
        c.rollback()


def test_tenant_can_still_update_its_billing_contact(temp_partner, runtime_engine):
    """The other half of the lifecycle boundary, and the case my first attempt
    broke.

    Blocking self-reactivation by revoking UPDATE on the whole partners table
    also killed billing-contact self-service (P4), which is a legitimate tenant
    action. 0011 kept it alive with a column-level grant. 0015 took that grant
    away too -- the partners policy is ungated, so the column sat outside the
    active-state gate and a stale request could still write it after a
    suspension committed -- and moved the write into a SECURITY DEFINER function
    that applies the gate itself.

    So the allowed side is still allowed; only the door moved. This pins that
    the door works; test_suspended_tenant_cannot_reactivate_itself pins the
    forbidden side, and test_lifecycle_gate pins that the old door is shut.
    Neither alone describes the boundary."""
    pid, _ = temp_partner
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        assert c.execute(text(
            "SELECT public.set_active_partner_billing_contact('billing@tenant.test')"
        )).scalar_one() is True
        c.commit()
        got = c.execute(text("SELECT billing_contact_email FROM partners WHERE id = :p"),
                        {"p": str(pid)}).scalar_one()
        assert got == "billing@tenant.test"
        c.rollback()


def test_active_tenant_still_cannot_touch_lifecycle_columns(temp_partner, runtime_engine):
    """The column grant must be exactly one column. An ACTIVE tenant is used
    here on purpose: the active-state gate is not what stops this, the missing
    column privilege is."""
    pid, _ = temp_partner
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        for col, val in [("status", "'active'"),
                         ("suspension_retention_until", "now()")]:
            sp = c.begin_nested()
            with pytest.raises(Exception):
                c.execute(text(f"UPDATE partners SET {col} = {val} WHERE id = :p"),
                          {"p": str(pid)})
            sp.rollback()
        c.rollback()


def test_tenant_can_still_read_its_own_partner_row(temp_partner, runtime_engine):
    """Tightness check on the revoke: SELECT must survive, or partner_is_active
    cannot evaluate and every gated policy fails closed for the wrong reason."""
    pid, _ = temp_partner
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', :p, false)"), {"p": str(pid)})
        assert c.execute(text("SELECT count(*) FROM partners")).scalar_one() == 1
        c.rollback()


def test_partners_policy_never_calls_the_active_function(platform_ctx):
    """Recursion guard, asserted against the catalog.

    partner_is_active() reads `partners`. If any policy ON partners calls it,
    every read of the table re-enters its own policy and Postgres dies with
    "stack depth limit exceeded" -- which is exactly how this migration failed
    the first time, taking 36 tests with it. FORCE ROW LEVEL SECURITY guarantees
    it for the owner too, so SECURITY DEFINER is not an escape.

    A comment saying "do not gate partners" is discipline. This is the check.
    """
    with platform_ctx() as c:
        offending = c.execute(text("""
            SELECT policyname FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'partners'
              AND (coalesce(qual, '') || coalesce(with_check, ''))
                  LIKE '%partner_is_active%'
        """)).scalars().all()
    assert offending == [], (
        f"policies {offending} on `partners` call partner_is_active(), whose "
        f"body reads `partners` -- unbounded recursion")


def test_every_partner_scoped_table_IS_gated(platform_ctx):
    """The other direction: the gate must be on all twelve, not merely on some.
    A tenant table whose policy forgot the active check is a suspended partner
    that can still write to it."""
    with platform_ctx() as c:
        ungated = c.execute(text("""
            SELECT tablename FROM pg_policies
            WHERE schemaname = 'public' AND policyname = 'partner_isolation'
              AND (coalesce(qual, '') NOT LIKE '%partner_is_active%'
                   OR coalesce(with_check, '') NOT LIKE '%partner_is_active%')
            ORDER BY tablename
        """)).scalars().all()
    assert ungated == [], f"partner_isolation without the active gate: {ungated}"

# --- suspended login --------------------------------------------------------

def test_no_new_session_is_issued_during_suspension(temp_partner, platform_engine):
    """A token minted during a suspension would become usable the moment the
    partner is reactivated -- a credential that outlives the state that should
    have prevented it. login() refuses instead."""
    from app.routers.auth import login, LoginBody
    from fastapi import HTTPException
    from app.auth.password import hash_password

    pid, uid = temp_partner
    with platform_engine.connect() as c:
        c.execute(text("UPDATE users SET hashed_password = :h WHERE id = :u"),
                  {"h": hash_password("correct-horse-battery"), "u": str(uid)})
        c.commit()
    _suspend(platform_engine, pid)

    with platform_engine.connect() as c:
        email = c.execute(text("SELECT email FROM users WHERE id = :u"),
                          {"u": str(uid)}).scalar_one()
        c.rollback()

    with pytest.raises(HTTPException) as exc:
        login(LoginBody(email=email, password="correct-horse-battery"))
    assert exc.value.status_code == 403


# --- activate vs purge ------------------------------------------------------

def test_activate_and_purge_cannot_both_win(temp_partner, platform_engine):
    """The lifecycle race. An expired-suspension purge and a concurrent activate
    contend on the partner row: exactly one outcome holds afterwards. The failure
    this rules out is 'purge deleted a partner that had just been reactivated'."""
    from app.services.maintenance import purge_expired_suspensions
    from sqlalchemy.orm import sessionmaker

    pid, _ = temp_partner
    # Make it look long-expired.
    with platform_engine.connect() as c:
        c.execute(text(
            "UPDATE partners SET status = 'suspended', suspended_at = now(), "
            "suspension_retention_until = now() - interval '1 day' WHERE id = :p"),
            {"p": str(pid)})
        c.commit()

    # Activate first, committed -- purge must then decline to delete it.
    with platform_engine.connect() as c:
        c.execute(text("UPDATE partners SET status = 'active', "
                       "suspension_retention_until = NULL WHERE id = :p"), {"p": str(pid)})
        c.commit()

    Maker = sessionmaker(bind=platform_engine, expire_on_commit=False)
    db = Maker()
    try:
        purged = purge_expired_suspensions(db)
        db.commit()
    finally:
        db.close()

    assert pid not in purged, "purge deleted a partner that had been reactivated"
    with platform_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM partners WHERE id = :p"),
                         {"p": str(pid)}).scalar_one() == 1
        c.rollback()


# --- redemption vs the lifecycle transitions --------------------------------

RACE_DOMAIN = "race.test"
RACE_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def pending_invite(temp_partner, platform_engine):
    """A committed inactive invitee, pending invitation, and queued mail.

    Committed, because a race needs two connections and one transaction cannot
    see another's rows. Torn down explicitly: temp_partner's teardown would
    reach these through ON DELETE CASCADE, but this fixture created them and
    leaning on a cascade it did not declare is how leftover rows outlive the
    test that made them.
    """
    pid, _ = temp_partner
    uid, inv_id, ev_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    token = f"race-{uuid.uuid4().hex}"
    email = f"invitee-{uid}@{RACE_DOMAIN}"

    with platform_engine.connect() as c:
        c.execute(text(
            "INSERT INTO users (id, email, partner_id, billing_source, is_active) "
            "VALUES (:u, :e, :p, 'partner', false)"),
            {"u": str(uid), "e": email, "p": str(pid)})
        c.execute(text(
            "INSERT INTO invitations (id, partner_id, user_id, email, token_hash, "
            "status, expires_at) VALUES "
            "(:i, :p, :u, :e, :h, 'pending', now() + interval '7 days')"),
            {"i": str(inv_id), "p": str(pid), "u": str(uid), "e": email,
             "h": hash_token(token)})
        c.execute(text(
            "INSERT INTO outbox_events (id, partner_id, invitation_id, event_type, "
            "recipient, token_ciphertext, token_nonce, key_version, status) VALUES "
            "(:v, :p, :i, 'invitation.created', :e, :c, :n, 1, 'pending')"),
            {"v": str(ev_id), "p": str(pid), "i": str(inv_id), "e": email,
             "c": b"race-ciphertext", "n": b"race-nonce1"})
        c.commit()

    yield SimpleNamespace(partner_id=pid, token=token, user_id=uid,
                          invitation_id=inv_id, event_id=ev_id, email=email)

    with platform_engine.connect() as c:
        c.execute(text("DELETE FROM outbox_events WHERE id = :v"), {"v": str(ev_id)})
        c.execute(text("DELETE FROM invitations WHERE id = :i"), {"i": str(inv_id)})
        c.execute(text("DELETE FROM users WHERE id = :u"), {"u": str(uid)})
        c.commit()


def _wait_until_blocked(engine, timeout=5.0):
    """Wait for one of our backends to be stuck on a lock.

    Polling for the observable condition rather than sleeping a fixed interval:
    a sleep long enough to be reliable on a loaded machine is also long enough
    to hide the case where nothing ever blocked. pg_stat_activity shows
    wait_event_type for backends belonging to the same role, and every
    connection here is app_platform.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as c:
            waiting = c.execute(text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() "
                "  AND wait_event_type = 'Lock'")).scalar_one()
            c.rollback()
        if waiting:
            return True
        time.sleep(0.05)
    return False


def _redeem_while(engine, transition, token):
    """Hold `transition` open, start a redemption that must block on it, then
    commit and report what the redemption decided.

    The assertion that the redemption actually WAITED is the load-bearing one.
    Without it this is two statements that happened to run in some order, and it
    would pass just as green if the lifecycle transition had finished before the
    redemption ever started -- which is the sequential case already covered
    elsewhere, wearing a thread as a disguise.
    """
    Maker = sessionmaker(bind=engine, expire_on_commit=False)
    outcome = {}

    def redeem():
        db = Maker()
        try:
            outcome["accepted"] = accept_invitation(db, token, RACE_PASSWORD)
            db.commit()
        except BaseException as exc:  # reported below, never swallowed
            outcome["error"] = exc
        finally:
            db.close()

    blocker = Maker()
    worker = threading.Thread(target=redeem, daemon=True)
    try:
        transition(blocker)          # takes the invitation row lock, uncommitted
        worker.start()
        assert _wait_until_blocked(engine), (
            "the redemption never waited on a lock, so the two transactions did "
            "not overlap and this proves nothing about the race")
        blocker.commit()
    finally:
        try:
            blocker.rollback()       # no-op after a successful commit
        finally:
            blocker.close()
        worker.join(timeout=15)

    assert not worker.is_alive(), "the redemption never finished"
    assert "error" not in outcome, f"redemption raised: {outcome.get('error')!r}"
    return outcome["accepted"]


def test_suspend_and_redemption_cannot_both_win(pending_invite, platform_engine):
    """The redemption is mid-flight when the suspension commits underneath it.

    Its UPDATE has already matched the invitation -- pending, unexpired, partner
    still active in its snapshot -- and is waiting for the row lock. What decides
    the outcome is what PostgreSQL re-checks when it unblocks. The partner check
    may well still read the pre-suspend state; `status = 'pending'` is on the
    target row, and suspension moved it to `revoked` in the same transaction.
    """
    accepted = _redeem_while(
        platform_engine,
        lambda db: suspend_partner(db, pending_invite.partner_id),
        pending_invite.token)
    assert accepted is False

    with platform_engine.connect() as c:
        assert c.execute(text("SELECT status FROM invitations WHERE id = :i"),
                         {"i": str(pending_invite.invitation_id)}).scalar_one() == "revoked"
        assert c.execute(text("SELECT is_active FROM users WHERE id = :u"),
                         {"u": str(pending_invite.user_id)}).scalar_one() is False
        assert c.execute(text("SELECT status FROM partners WHERE id = :p"),
                         {"p": str(pending_invite.partner_id)}).scalar_one() == "suspended"
        c.rollback()


def test_domain_deactivation_and_redemption_cannot_both_win(pending_invite, platform_engine):
    """Same overlap, the other transition.

    Worth its own test rather than a parametrise: domain deactivation reaches
    the invitation by a different route -- scan users on the domain, then narrow
    the revocation to those user ids -- and that narrowing is where an empty
    match, a stale is_active filter, or a lost user would silently leave the
    invitation pending while the operator was told the domain was handled.
    """
    accepted = _redeem_while(
        platform_engine,
        lambda db: deactivate_domain(db, pending_invite.partner_id, RACE_DOMAIN),
        pending_invite.token)
    assert accepted is False

    with platform_engine.connect() as c:
        assert c.execute(text("SELECT status FROM invitations WHERE id = :i"),
                         {"i": str(pending_invite.invitation_id)}).scalar_one() == "revoked"
        assert c.execute(text("SELECT is_active FROM users WHERE id = :u"),
                         {"u": str(pending_invite.user_id)}).scalar_one() is False
        # And the mail for a revoked invitation is terminal and secret-free.
        ev = c.execute(text(
            "SELECT status, token_ciphertext FROM outbox_events WHERE id = :v"),
            {"v": str(pending_invite.event_id)}).one()
        assert ev.status == "failed" and ev.token_ciphertext is None
        c.rollback()
