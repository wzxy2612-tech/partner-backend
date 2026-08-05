"""One-shot outbox dispatcher: `python -m app.dispatcher`.

WHAT THIS CLOSES

/onboarding/commit wrote a pending event and nothing ever sent it. No worker, no
cron, no endpoint, no compose service. Invited users stayed inactive and never
received a token, and every hardening applied to the outbox was hardening on a
queue that had no consumer.

WHY ONE SHOT AND NOT A LOOP

A resident worker needs supervision, health checks, graceful shutdown and a
restart policy -- deployment topology, none of which makes the delivery argument
any stronger. This runs, drains what is due, prints what it did, and exits, so
the scheduler is whatever the environment already has: cron, a Kubernetes
CronJob, a Cloud Run Job, `docker compose run --rm dispatcher`.

WHY IT BUILDS ITS OWN ENGINE

app.db creates the runtime and platform engines at import, so anything importing
it holds those credentials. This module is the only thing that should hold the
dispatcher's, and the API process should never have them -- which is the entire
point of a separate role. So the connection is made here, from an environment
variable this process is given and the API container is not.

Exit codes: 0 if the batch completed, 1 if configuration or the database
refused. A scheduler needs to be able to tell "nothing to do" from "could not
run", and both of those are silent successes if you only look at stdout.
"""
from __future__ import annotations

import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services.email import EmailConfigError, resolve_sender
from app.services.outbox import dispatch_pending
from app.services.outbox_crypto import validate_outbox_config

URL_ENV = "DISPATCHER_DATABASE_URL"
BATCH_ENV = "DISPATCHER_BATCH_LIMIT"


def run(limit: int = 100) -> int:
    """Drain up to `limit` due events. Returns a process exit code."""
    url = os.environ.get(URL_ENV, "").strip()
    if not url:
        print(f"{URL_ENV} is unset. The dispatcher connects as app_dispatcher, "
              f"not as the API's roles; see docker-compose.yml.", file=sys.stderr)
        return 1

    # Fail on configuration before touching the database, so a missing key is a
    # message about the key rather than a half-drained batch. Two gates, not
    # one: keys and senders are different questions, and the API process needs
    # the first without the second.
    validate_outbox_config()
    try:
        sender = resolve_sender()
    except EmailConfigError as exc:
        # Not an exception to propagate. A dispatcher with no delivering sender
        # is a scheduling mistake, and the scheduler reads the exit code -- what
        # it must not do is drain the queue into a print statement, mark every
        # row sent, and clear the ciphertext that was the only copy of the token.
        print(str(exc), file=sys.stderr)
        return 1

    engine = create_engine(url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        result = dispatch_pending(session, sender, limit=limit)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()

    # Terminated is reported separately from sent because they are different
    # events operationally: one is mail going out, the other is mail that never
    # will, and a scheduler log that folds them together hides a backlog turning
    # into a graveyard.
    print(f"dispatched: sent={len(result.sent)} retried={len(result.retried)} "
          f"dead_lettered={len(result.dead_lettered)} "
          f"terminated={len(result.terminated)}")
    return 0


def main() -> int:
    raw = os.environ.get(BATCH_ENV, "").strip()
    try:
        limit = int(raw) if raw else 100
    except ValueError:
        print(f"{BATCH_ENV}={raw!r} is not an integer", file=sys.stderr)
        return 1
    try:
        return run(limit)
    except Exception as exc:
        # The type and message, never the payload: this process handles
        # plaintext invitation tokens and its stderr goes to a log aggregator.
        print(f"dispatch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
