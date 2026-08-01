"""Pluggable invitation delivery. Production wiring (SMTP/provider) drops in
behind the same interface; tests use OutboxEmailSender to capture what was sent.
"""
from typing import Protocol


class EmailSender(Protocol):
    def send_invitation(self, email: str, token: str) -> None: ...


class ConsoleEmailSender:
    """Default sender: logs instead of delivering. Tokens are truncated so a full
    live token never lands in logs."""
    def send_invitation(self, email: str, token: str) -> None:
        print(f"[invite] -> {email}  (token {token[:8]}...)")


class OutboxEmailSender:
    """Captures sent invitations in memory for assertions in tests."""
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_invitation(self, email: str, token: str) -> None:
        self.sent.append((email, token))
