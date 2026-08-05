"""The dispatcher will not run without a sender that delivers.

dispatch_pending marks an event `sent` and clears its ciphertext and nonce on
the strength of send_invitation() returning. It cannot distinguish a provider
acknowledgement from a print statement, so a non-delivering sender does not fail
to send -- it consumes the event. The invitation stays pending, the only copy of
the token is gone, and the batch reports success.

The dispatcher used to construct ConsoleEmailSender as its default. These pin
that the default is gone rather than narrowed, which is the shape OUTBOX_KEYS
settled on when it stopped inventing an all-zero key.

No database: every refusal here happens before create_engine, and that ordering
is one of the things being pinned.
"""
import pytest

from app.dispatcher import URL_ENV, run
from app.services.email import (DELIVERING_SENDERS, SENDER_ENV,
                                ConsoleEmailSender, EmailConfigError,
                                resolve_sender)


def test_an_unnamed_sender_is_refused(monkeypatch):
    monkeypatch.delenv(SENDER_ENV, raising=False)
    with pytest.raises(EmailConfigError) as exc:
        resolve_sender()
    assert SENDER_ENV in str(exc.value)


def test_console_cannot_be_named(monkeypatch):
    """It is not that `console` is rejected by a check -- it is not in the
    registry, so there is no name that reaches it. A check can be relaxed by
    the next person who finds it inconvenient; an absent entry has to be
    written back in deliberately, and that is a visible diff."""
    assert "console" not in DELIVERING_SENDERS
    assert ConsoleEmailSender not in DELIVERING_SENDERS.values()

    monkeypatch.setenv(SENDER_ENV, "console")
    with pytest.raises(EmailConfigError):
        resolve_sender()


def test_a_registered_sender_is_returned(monkeypatch):
    """The refusal must be about the registry, not about refusing everything.

    Without this, an empty DELIVERING_SENDERS and a resolve_sender that always
    raised would be indistinguishable -- and the day someone registers a real
    provider, nothing would have told them the path works.
    """
    made = []

    class Fake:
        def send_invitation(self, email: str, token: str) -> None:
            made.append((email, token))

    monkeypatch.setitem(DELIVERING_SENDERS, "fake", Fake)
    monkeypatch.setenv(SENDER_ENV, "fake")
    assert isinstance(resolve_sender(), Fake)


def test_the_dispatcher_exits_nonzero_before_touching_the_database(monkeypatch):
    """The URL is set and deliberately unusable. If the sender gate ran after
    create_engine this would raise a connection error instead of returning 1,
    so the exit code is what proves the ordering."""
    monkeypatch.setenv(URL_ENV, "postgresql+psycopg://nobody@127.0.0.1:1/nowhere")
    monkeypatch.delenv(SENDER_ENV, raising=False)
    assert run(limit=1) == 1
