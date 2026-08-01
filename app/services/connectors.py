"""Partner connectors (integrations) and their verification state. All RLS-scoped
to the caller's partner."""
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def register_connector(db: OrmSession, partner_id: UUID, kind: str,
                       config: dict | None = None) -> UUID:
    cid = uuid4()
    import json
    db.execute(text(
        "INSERT INTO connectors (id, partner_id, kind, status, config) "
        "VALUES (:id, :p, :k, 'unverified', cast(:c AS jsonb)) "
        "ON CONFLICT (partner_id, kind) DO UPDATE SET config = EXCLUDED.config"),
        {"id": str(cid), "p": str(partner_id), "k": kind, "c": json.dumps(config or {})})
    return cid


def verify_connector(db: OrmSession, partner_id: UUID, kind: str) -> bool:
    """Mark a connector verified. (A real implementation would test the live
    connection here; we record the outcome.)"""
    n = db.execute(text(
        "UPDATE connectors SET status = 'verified', verified_at = now() "
        "WHERE partner_id = :p AND kind = :k"),
        {"p": str(partner_id), "k": kind}).rowcount
    return n > 0


def verified_kinds(db: OrmSession) -> set[str]:
    return {k for (k,) in db.execute(
        text("SELECT kind FROM connectors WHERE status = 'verified'"))}
