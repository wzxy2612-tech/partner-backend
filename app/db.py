from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

# Runtime path: partner-facing requests. Connects as app_runtime (NOBYPASSRLS),
# so RLS is always in force no matter what the query says.
runtime_engine = create_engine(settings.runtime_database_url, pool_pre_ping=True)

# Platform path: direct-customer / platform-admin / Stripe webhooks. Connects as
# app_platform (BYPASSRLS) -- this is the unchanged pre-existing app behaviour.
platform_engine = create_engine(settings.platform_database_url, pool_pre_ping=True)

RuntimeSession = sessionmaker(bind=runtime_engine, autoflush=False, expire_on_commit=False)
PlatformSession = sessionmaker(bind=platform_engine, autoflush=False, expire_on_commit=False)

# partner_id for platform/direct rows. Uniform equality policies then work with a
# single rule and no BYPASSRLS special-casing in the common path.
PLATFORM_PARTNER_ID = UUID("00000000-0000-0000-0000-000000000000")


@contextmanager
def partner_session(partner_id: UUID) -> Iterator[Session]:
    """A DB session scoped to exactly one partner.

    The tenant boundary is applied with set_config(..., is_local=True), i.e.
    SET LOCAL: it lives only for this transaction and is discarded on
    commit/rollback, which makes it safe under connection pooling.

    `partner_id` MUST come from the server-resolved authenticated principal --
    never from client input. The whole isolation guarantee rests on that.
    """
    session: Session = RuntimeSession()
    try:
        session.execute(
            text("SELECT set_config('app.partner_id', :pid, true)"),
            {"pid": str(partner_id)},
        )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def platform_session() -> Iterator[Session]:
    """A DB session for platform / direct-customer / webhook work (BYPASSRLS)."""
    session: Session = PlatformSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
