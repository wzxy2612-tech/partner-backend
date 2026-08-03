"""The cross-tenant outbox hole, pinned shut (0014).

WHAT THIS REPRODUCES

Before 0014, outbox_events had no row security and app_runtime held full DML on
it by default privilege. The reported attack was three statements long:

    Partner B onboards a user -> pending invitation + pending outbox event
    Partner A: UPDATE outbox_events SET recipient = 'attacker@...' WHERE id = <B's>
    the dispatcher decrypts B's token and mails it to the attacker

Every test here is that sequence, stopped at step two.

WHY THIS FILE COMMITS AND test_outbox.py DOES NOT

The rest of the outbox suite runs inside one rolled-back transaction, which is
the right shape for testing atomicity. It is the wrong shape here: an attacker
reading another tenant's row is two sessions, and a row that exists only inside
the reader's own uncommitted transaction is not the thing under test. Proving
isolation against data this session wrote itself would prove something weaker
than it appears to -- so the victim's rows are committed by a separate platform
connection and torn down explicitly.

Explicitly, not by cascade. conftest's `ids` fixture does not list
outbox_events; those rows disappear today only because invitations does and the
FK is ON DELETE CASCADE. That is true, undocumented, and not something a test
that creates committed rows should lean on.
"""
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

ATTACKER = "attacker@evil.test"


def _sqlstate(exc):
    """The SQLSTATE, not the message text.

    A WITH CHECK violation has no constraint_name to match on, so the structured
    field available is the five-character code. Asserting on the English string
    ("new row violates row-level security policy...") would make the test
    dependent on server locale and wording -- the same reason onboarding.py
    matches diag.constraint_name instead of parsing error text.
    """
    orig = exc.value.orig
    return (getattr(orig, "sqlstate", None)
            or getattr(getattr(orig, "diag", None), "sqlstate", None))


@pytest.fixture()
def b_event(ids, platform_engine):
    """One committed pending outbox event belonging to Partner B.

    Seeded on the platform path (BYPASSRLS) because that is the only role that
    can write across tenants, which is precisely the property the tests below
    assert app_runtime does not have.
    """
    inv_id, ev_id = uuid.uuid4(), uuid.uuid4()
    recipient = "victim@b.test"

    with platform_engine.begin() as c:
        c.execute(text(
            "INSERT INTO invitations (id, partner_id, user_id, email, token_hash, "
            "status, expires_at) VALUES "
            "(:i, :p, :u, :e, :h, 'pending', now() + interval '7 days')"),
            {"i": str(inv_id), "p": str(ids.partner_b), "u": str(ids.user_b),
             "e": recipient, "h": "b" * 64})
        c.execute(text(
            "INSERT INTO outbox_events (id, partner_id, invitation_id, event_type, "
            "recipient, token_ciphertext, token_nonce, key_version, status) VALUES "
            "(:v, :p, :i, 'invitation.created', :r, :c, :n, 1, 'pending')"),
            {"v": str(ev_id), "p": str(ids.partner_b), "i": str(inv_id),
             "r": recipient, "c": b"stand-in-ciphertext", "n": b"stand-in-nc"})

    # Positive control. Every assertion in this file is of the form "A sees
    # nothing / changes nothing", and all of them pass for free if the row was
    # never written. This project has shipped a test that matched zero rows and
    # called it green; the guard against repeating that belongs here, where it
    # runs once per test rather than in one test that could be skipped.
    with platform_engine.connect() as c:
        assert c.execute(text(
            "SELECT count(*) FROM outbox_events WHERE id = :v"),
            {"v": str(ev_id)}).scalar_one() == 1, (
            "the victim event was not committed; every test in this file would "
            "pass vacuously")

    yield SimpleNamespace(event_id=ev_id, invitation_id=inv_id, recipient=recipient)

    with platform_engine.begin() as c:
        c.execute(text("DELETE FROM outbox_events WHERE partner_id = :p"),
                  {"p": str(ids.partner_b)})
        c.execute(text("DELETE FROM invitations WHERE partner_id = :p"),
                  {"p": str(ids.partner_b)})


def _recipient_now(platform_engine, event_id):
    with platform_engine.connect() as c:
        return c.execute(text("SELECT recipient FROM outbox_events WHERE id = :v"),
                         {"v": str(event_id)}).scalar_one_or_none()


# --- read -------------------------------------------------------------------

def test_another_tenants_event_is_invisible(ids, partner_ctx, b_event):
    """The ciphertext is AEAD-sealed, but 0013 shipped with a fixed all-zero key
    whenever OUTBOX_KEYS is unset -- which the bundled compose file leaves
    unset. So "A can read the row" and "A can recover the token" were the same
    sentence. The policy is what stops the read.
    """
    with partner_ctx(ids.partner_a) as c:
        rows = c.execute(text(
            "SELECT id, recipient, token_ciphertext FROM outbox_events "
            "WHERE id = :v"), {"v": str(b_event.event_id)}).all()
    assert rows == []


# --- the reported attack ----------------------------------------------------

def test_another_tenants_recipient_cannot_be_redirected(
        ids, partner_ctx, platform_engine, b_event):
    """The exact statement from the report.

    Note what a blocked UPDATE looks like under RLS: not an error, but zero rows
    affected. Application code that checks only for an exception would read this
    as success, which is why the assertion is on rowcount AND on the value the
    victim's row still holds. One of those alone would be half a test.
    """
    with partner_ctx(ids.partner_a) as c:
        result = c.execute(text(
            "UPDATE outbox_events SET recipient = :bad WHERE id = :v"),
            {"bad": ATTACKER, "v": str(b_event.event_id)})
        assert result.rowcount == 0

    assert _recipient_now(platform_engine, b_event.event_id) == b_event.recipient


# --- destroy ----------------------------------------------------------------

def test_another_tenants_event_cannot_be_deleted(
        ids, partner_ctx, platform_engine, b_event):
    """Denial of delivery is a smaller harm than redirection and a real one: a
    tenant that can drop a competitor's queued mail suppresses their onboarding
    silently, because the dispatcher has nothing to fail on.
    """
    with partner_ctx(ids.partner_a) as c:
        result = c.execute(text("DELETE FROM outbox_events WHERE id = :v"),
                           {"v": str(b_event.event_id)})
        assert result.rowcount == 0

    assert _recipient_now(platform_engine, b_event.event_id) == b_event.recipient


# --- forge ------------------------------------------------------------------

def test_an_event_cannot_be_enqueued_under_another_tenants_id(
        ids, partner_ctx, b_event):
    """WITH CHECK, not the foreign key.

    Referential integrity checks run exempt from RLS -- that exemption is what
    makes the composite tenant foreign keys work at all (0007), and it means the
    FK to invitations(id, partner_id) resolves happily against Partner B's row
    even from Partner A's session. Nothing about the FK objects to this insert.
    The WITH CHECK half of the policy is the only thing that does.
    """
    with partner_ctx(ids.partner_a) as c:
        with pytest.raises(DBAPIError) as exc:
            c.execute(text(
                "INSERT INTO outbox_events (partner_id, invitation_id, event_type, "
                "recipient, token_ciphertext, token_nonce, key_version, status) "
                "VALUES (:p, :i, 'invitation.created', :r, :c, :n, 1, 'pending')"),
                {"p": str(ids.partner_b), "i": str(b_event.invitation_id),
                 "r": ATTACKER, "c": b"forged", "n": b"forged-nonce"})
    assert _sqlstate(exc) == "42501", (
        f"expected a row-level security violation (42501), got {_sqlstate(exc)}")
