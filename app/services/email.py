"""Pluggable invitation delivery. Production wiring (SMTP/provider) drops in
behind the same interface; tests use OutboxEmailSender to capture what was sent.

WHY THE DISPATCHER CANNOT PICK A SENDER FOR ITSELF

dispatch_pending marks an event `sent` and destroys its ciphertext and nonce on
the strength of send_invitation() returning without raising. It has no way to
tell a provider acknowledgement from a print statement -- both are "returned
normally". So a non-delivering sender does not merely fail to send: it consumes
the event irreversibly, and the invitation stays pending with no token left to
re-deliver. The user cannot finish onboarding and nothing anywhere is red.

The dispatcher used to construct ConsoleEmailSender itself, as a default. The
fix is the same shape the keyring took when it stopped inventing an all-zero
key: the default is gone rather than narrowed. A sender must be named, and the
names that can be named are only senders that deliver.

Deciding this on APP_ENV was considered and rejected. That is precisely the
branch OUTBOX_KEYS removed -- every deployment that had not thought about
APP_ENV was every deployment that had not thought about delivery either, and it
would hand exactly those the sender that eats tokens.
"""
import os
from typing import Callable, Protocol


class EmailSender(Protocol):
    def send_invitation(self, email: str, token: str) -> None: ...


class EmailConfigError(RuntimeError):
    """No usable sender is configured. Raised at startup, never mid-batch."""


SENDER_ENV = "OUTBOX_SENDER"


class ConsoleEmailSender:
    """Prints instead of delivering. Tokens are truncated so a full live token
    never lands in logs.

    NOT in DELIVERING_SENDERS, and that absence is the whole point -- it is not
    a sender the dispatcher can be configured into using by accident. Import it
    directly if you want it in a demo, and know that whatever consumes its
    result will believe the mail went out.
    """
    def send_invitation(self, email: str, token: str) -> None:
        print(f"[invite] -> {email}  (token {token[:8]}...)")


class OutboxEmailSender:
    """Captures sent invitations in memory for assertions in tests."""
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_invitation(self, email: str, token: str) -> None:
        self.sent.append((email, token))


# name -> constructor. Only senders that actually hand the mail to something
# that delivers it. EMPTY in this build: no provider integration has been
# written, so `make dispatch` refuses at startup rather than draining the queue
# into a print statement. Registering an SMTP or provider sender here is the
# one change that makes the dispatcher runnable, and that is the intended shape
# -- delivery becomes possible at the same moment something can actually
# deliver, not before.
DELIVERING_SENDERS: dict[str, Callable[[], EmailSender]] = {}


def resolve_sender() -> EmailSender:
    """The sender this process is configured to use, or a refusal.

    Called from the dispatcher's startup path, beside validate_outbox_config and
    before any database connection, so an unusable configuration is a message
    about the configuration rather than a half-drained batch.

    It is NOT folded into validate_outbox_config: keys and senders are two
    different questions, and one function answering both would have to be
    consulted by callers that only care about one of them. The API process
    validates keys because it encrypts; it never sends, so it must not be
    required to name a sender.
    """
    known = ", ".join(sorted(DELIVERING_SENDERS)) or "(none registered)"
    raw = os.environ.get(SENDER_ENV, "").strip().lower()

    if not raw:
        raise EmailConfigError(
            f"{SENDER_ENV} is unset and there is no default. A successful send "
            f"marks the event sent and destroys the token, so the dispatcher "
            f"will not run with a sender that might not deliver. "
            f"Delivering senders: {known}. ConsoleEmailSender is deliberately "
            f"not among them.")

    if raw not in DELIVERING_SENDERS:
        raise EmailConfigError(
            f"{SENDER_ENV}={raw!r} is not a delivering sender. "
            f"Delivering senders: {known}.")

    return DELIVERING_SENDERS[raw]()
