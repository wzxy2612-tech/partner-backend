"""Partner connectors (integrations) and their verification state. All RLS-scoped
to the caller's partner."""
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def register_connector(db: OrmSession, partner_id: UUID, kind: str,
                       config: dict | None = None) -> tuple[UUID, str]:
    """Register or re-register a connector. Returns the (id, status) that was
    actually persisted.

    Three bugs lived in the old conflict branch, all the same mistake -- the
    caller was told what the code assumed instead of what the row said:

      * config was updated but `status` stayed `verified` and `verified_at`
        stayed set, so re-pointing a verified connector at new credentials kept
        its verified standing. Workflow template cloning gates on exactly that
        flag, which made it an authorization bypass rather than cosmetic.
      * the freshly generated UUID was returned even when the conflict branch
        kept the existing row, so the returned id named a row that did not
        exist.
      * the router then reported a hardcoded "unverified" regardless.

    Changing the config invalidates the verification, because what was verified
    was the old config. RETURNING makes the database the one that answers.
    """
    import json
    row = db.execute(text(
        "INSERT INTO connectors (id, partner_id, kind, status, config) "
        "VALUES (:id, :p, :k, 'unverified', cast(:c AS jsonb)) "
        "ON CONFLICT (partner_id, kind) DO UPDATE SET "
        "  config = EXCLUDED.config, status = 'unverified', verified_at = NULL "
        "RETURNING id, status"),
        {"id": str(uuid4()), "p": str(partner_id), "k": kind,
         "c": json.dumps(config or {})}).one()
    return row.id, row.status


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
