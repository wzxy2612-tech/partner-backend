"""What app_dispatcher can reach, and what it cannot.

The role exists because the outbox had no consumer (#2) and the obvious consumer
-- app_platform -- is BYPASSRLS over the whole database. A dispatcher is a small
program with one job, and the blast radius of the smallest component should not
be the largest one.

Its cross-tenant reach comes from three `USING (true)` policies rather than the
role attribute. That is BYPASSRLS for those three tables, spelled longer; what
it buys is that a fourth table is unreachable until someone writes a policy
naming this role, which is not true of the attribute.

So the tests come in pairs. Every "cannot" below is worthless without the
matching "can" -- a role that could reach nothing at all would pass all the
refusals and deliver no mail, which is the bug this role was created to fix.

This file commits. Two roles cannot see each other's uncommitted rows, and the
whole question here is what a different connection is allowed to do.
"""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.services import outbox
from app.services.email import OutboxEmailSender


def _sqlstate(exc):
    orig = exc.value.orig
    return (getattr(orig, "sqlstate", None)
            or getattr(getattr(orig, "diag", None), "sqlstate", None))


@pytest.fixture()
def queued(ids, platform_engine):
    """One committed pending event for partner A and one for partner B.

    Two tenants on purpose: the dispatcher's job is to see both, and a fixture
    with one partner could not tell "reaches across tenants" from "reaches its
    own".
    """
    made = []
    Maker = sessionmaker(bind=platform_engine, expire_on_commit=False)
    db = Maker()
    for partner_id in (ids.partner_a, ids.partner_b):
        uid, inv_id = uuid.uuid4(), uuid.uuid4()
        email = f"inv-{uuid.uuid4().hex[:8]}@dispatcher.test"
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
        made.append({"partner_id": partner_id, "user_id": uid,
                     "invitation_id": inv_id, "event_id": event_id})
    db.commit()
    db.close()

    yield made

    db = Maker()
    for m in made:
        db.execute(text("DELETE FROM outbox_events WHERE id = :v"),
                   {"v": str(m["event_id"])})
        db.execute(text("DELETE FROM invitations WHERE id = :i"),
                   {"i": str(m["invitation_id"])})
        db.execute(text("DELETE FROM users WHERE id = :u"),
                   {"u": str(m["user_id"])})
    db.commit()
    db.close()


# --- the guard's own precondition -------------------------------------------

def test_the_dispatcher_does_not_bypass_row_security(platform_engine):
    """Checked first, because it is the assumption every other test here rests
    on.

    A dispatcher provisioned with BYPASSRLS would not FAIL anything below -- row
    security simply would not apply to it, so "it can only see what its policies
    allow" would be true of nothing and every refusal would be untested. 0018
    refuses to run against such a role for the same reason.
    """
    with platform_engine.connect() as c:
        row = c.execute(text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname = 'app_dispatcher'")).one_or_none()
        c.rollback()
    assert row is not None, (
        "app_dispatcher does not exist; run `make provision-dispatcher`")
    assert not row.rolsuper and not row.rolbypassrls


# --- can: the reach it needs -------------------------------------------------

def test_the_dispatcher_sees_events_from_every_tenant(queued, dispatcher_engine):
    """The positive control for the whole file.

    Without a policy on outbox_events this returns nothing -- and so does every
    refusal test below, for the wrong reason.
    """
    wanted = {m["event_id"] for m in queued}
    with dispatcher_engine.connect() as c:
        seen = set(c.execute(text(
            "SELECT id FROM outbox_events WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(i) for i in wanted]}).scalars().all())
        c.rollback()
    assert seen == wanted


def test_the_dispatcher_can_read_partner_state_through_the_shared_function(
        queued, dispatcher_engine):
    """partner_is_active() is SECURITY INVOKER, so it reads `partners` as
    whoever called it. Without the policy on that table it returns false for
    every partner and the claim matches nothing -- silently, forever. The
    dispatcher would run, report success and deliver nothing: the exact symptom
    it was built to fix.
    """
    with dispatcher_engine.connect() as c:
        active = c.execute(text("SELECT public.partner_is_active(:p)"),
                           {"p": str(queued[0]["partner_id"])}).scalar_one()
        c.rollback()
    assert active is True


def test_the_dispatcher_can_deliver_end_to_end(queued, dispatcher_engine):
    """Claim, decrypt, send, record -- as app_dispatcher, through the real
    service. Everything above is a permission; this is the job.
    """
    Maker = sessionmaker(bind=dispatcher_engine, expire_on_commit=False)
    db = Maker()
    try:
        sender = OutboxEmailSender()
        result = outbox.dispatch_pending(db, sender)
        db.commit()
    finally:
        db.close()

    wanted = {m["event_id"] for m in queued}
    assert wanted <= set(result.sent)
    assert len(sender.sent) >= len(wanted)

    with dispatcher_engine.connect() as c:
        rows = c.execute(text(
            "SELECT status, token_ciphertext IS NULL AS clean, sent_at "
            "FROM outbox_events WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": [str(i) for i in wanted]}).all()
        c.rollback()
    assert all(r.status == "sent" and r.clean and r.sent_at for r in rows)


# --- cannot: the reach it must not have --------------------------------------

def test_the_dispatcher_cannot_redirect_an_event(queued, dispatcher_engine):
    """The policy is USING (true), so row security would happily allow this. The
    column grant is the only thing that refuses it -- which is the division of
    labour on purpose: the policy answers which rows, the grant answers which
    facts about them.
    """
    with dispatcher_engine.connect() as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text(
                "UPDATE outbox_events SET recipient = 'attacker@evil.test' "
                "WHERE id = :v"), {"v": str(queued[0]["event_id"])})
        c.rollback()
    assert _sqlstate(exc) == "42501"


def test_the_dispatcher_cannot_move_an_event_to_another_tenant(
        queued, dispatcher_engine):
    """USING (true) with a table-level UPDATE grant would let this role rewrite
    partner_id and reassign another tenant's mail to itself.
    """
    with dispatcher_engine.connect() as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text(
                "UPDATE outbox_events SET partner_id = :p WHERE id = :v"),
                {"p": str(queued[1]["partner_id"]),
                 "v": str(queued[0]["event_id"])})
        c.rollback()
    assert _sqlstate(exc) == "42501"


def test_the_dispatcher_cannot_read_an_invitation_token_hash(
        queued, dispatcher_engine):
    """It needs `status` and `expires_at` to decide deliverability and has no
    use for the hash -- which is the value that makes a leaked invitations row
    the start of an account takeover rather than a list of email addresses.
    """
    with dispatcher_engine.connect() as c:
        # The columns it does need are readable.
        assert c.execute(text(
            "SELECT status FROM invitations WHERE id = :i"),
            {"i": str(queued[0]["invitation_id"])}).scalar_one() == "pending"
        with pytest.raises(DBAPIError) as exc:
            c.execute(text("SELECT token_hash FROM invitations WHERE id = :i"),
                      {"i": str(queued[0]["invitation_id"])})
        c.rollback()
    assert _sqlstate(exc) == "42501"


def test_the_dispatcher_cannot_reach_a_table_nobody_granted_it(dispatcher_engine):
    """The property the role attribute could not have given.

    BYPASSRLS applies to every table that exists and every table added later --
    which is how outbox_events shipped world-writable the day it was created.
    Three policies apply to three tables, and a fourth is unreachable until
    someone writes one naming this role.
    """
    with dispatcher_engine.connect() as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text("SELECT id FROM users LIMIT 1"))
        c.rollback()
    assert _sqlstate(exc) == "42501"


def test_the_dispatcher_cannot_write_the_partner_lifecycle(
        queued, dispatcher_engine):
    """It reads `partners` to answer one question. Reading is not writing, and
    the grant says so rather than the policy, which is `USING (true)` here.
    """
    with dispatcher_engine.connect() as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text("UPDATE partners SET status = 'suspended' WHERE id = :p"),
                      {"p": str(queued[0]["partner_id"])})
        c.rollback()
    assert _sqlstate(exc) == "42501"
