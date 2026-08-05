"""Print the plaintext invitation token for a queued outbox row. LOCAL ONLY.

WHY THIS EXISTS

DELIVERING_SENDERS is empty, so `make dispatch` exits 1 and no invitation mail
is ever produced locally. A frontend cannot build the activation page without a
redeemable token. The alternative -- registering a fake sender -- is exactly the
path 0021 removed, and it would consume real events and destroy their
ciphertext. Reading the queue without consuming it does not.

WHY IT IS GATED

This is a decryption oracle. It reads OUTBOX_KEYS and writes plaintext tokens to
stdout, which is the single thing the outbox encryption exists to prevent. It
cannot be made structurally unreachable the way ConsoleEmailSender was, because
decrypting IS its purpose -- so it takes the next best shape: it must be named.
ALLOW_TOKEN_DECRYPT has no default, for the same reason OUTBOX_SENDER has none.
An environment that has not thought about this variable is an environment that
should not be running this.

It also lives in tools/dev/ rather than scripts/, so that `ls scripts/` does not
show it next to provision_dispatcher_role.sql as though it were an operational
tool, and the filename says dev out loud.

USE

    docker compose exec -T \
        -e ALLOW_TOKEN_DECRYPT=i-understand \
        -e PYTHONPATH=/app \
        api python3 tools/dev/dev_decode_invite_token.py

Invoked as a path with PYTHONPATH=/app, not -m. A site-packages `tools` package
exists in the container, so `-m tools.dev...` resolves to site-packages (a regular
package with __init__.py overriding namespace packages) rather than /app/tools.
PYTHONPATH=/app ensures `import app` resolves on the success path.

The token goes to POST /invitations/accept as {"token": ..., "password": ...}.
The password has a 12 character floor; a shorter one is a 422, not a 400.
"""
import os
import sys

GATE_ENV = "ALLOW_TOKEN_DECRYPT"
GATE_VALUE = "i-understand"

# Reads across tenants on purpose: local development wants every queued
# invitation, not the ones one partner can see. app_runtime holds column-scoped
# INSERT on outbox_events and no SELECT at all since 0019, so it cannot do this;
# app_dispatcher sees only what its three policies allow. Naming app_platform
# here rather than leaving a choice keeps the next person from picking the role
# that happens to work rather than the one that is right.
ROLE = "app_platform"


def main() -> int:
    if os.environ.get(GATE_ENV) != GATE_VALUE:
        print(
            f"{GATE_ENV} is not set to {GATE_VALUE!r}.\n"
            f"This prints plaintext invitation tokens decrypted from the outbox "
            f"queue -- the one thing that encryption exists to prevent. It has "
            f"no default and never runs by accident. Local development only; "
            f"never point it at a database anyone else uses.",
            file=sys.stderr)
        return 1

    # Imported after the gate so that a refusal costs nothing and, more to the
    # point, so that a refused run never constructs a keyring at all.
    from sqlalchemy import text

    from app.db import platform_engine
    from app.services.outbox_crypto import build_aad, decrypt_token

    with platform_engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, partner_id, invitation_id, event_type, recipient, "
            "       token_ciphertext, token_nonce, key_version, available_at "
            "FROM outbox_events "
            "WHERE status = 'pending' "
            "  AND token_ciphertext IS NOT NULL "
            "ORDER BY available_at DESC")).all()
        conn.rollback()

    if not rows:
        print("no pending outbox rows with a payload. Run a CSV onboarding "
              "first, or the tokens have already been dispatched.",
              file=sys.stderr)
        return 1

    for r in rows:
        aad = build_aad(event_id=r.id, invitation_id=r.invitation_id,
                        partner_id=r.partner_id, event_type=r.event_type)
        try:
            token = decrypt_token(r.token_ciphertext, r.token_nonce,
                                  r.key_version, aad)
        except Exception as exc:
            # The type only. This tool has no more right to persist or print a
            # provider's or a library's message than dispatch_pending does.
            print(f"{r.recipient}\tundecryptable ({type(exc).__name__}) -- "
                  f"key_version {r.key_version}", file=sys.stderr)
            continue
        print(f"{r.recipient}\t{token}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
