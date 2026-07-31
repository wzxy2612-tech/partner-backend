"""The authenticated principal and how it is resolved.

Authentication runs on the platform path (BYPASSRLS) because it must read the
session/user/partner rows BEFORE any tenant scope exists. The resolved
partner_id then drives which DB path (and RLS scope) the request runs under --
the client never supplies it.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session as OrmSession

from app.auth.tokens import hash_token
from app.models.session import Session as SessionRow
from app.models.user import User
from app.models.partner import Partner
from app.models.membership import Membership
from app.models.enums import Role, PartnerStatus

NIL = UUID("00000000-0000-0000-0000-000000000000")


@dataclass
class Principal:
    user_id: UUID
    partner_id: UUID
    is_platform: bool
    roles: list[Role] = field(default_factory=list)
    partner_status: PartnerStatus | None = None

    @property
    def is_suspended(self) -> bool:
        return self.partner_status == PartnerStatus.suspended

    def has_role(self, role: Role) -> bool:
        return role in self.roles


def authenticate(db: OrmSession, token: str | None) -> Principal | None:
    """Resolve a bearer token to a Principal, or None if it is not usable."""
    if not token:
        return None
    row = db.query(SessionRow).filter(SessionRow.token_hash == hash_token(token)).one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        return None

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        return None

    partner_id = user.partner_id
    is_platform = partner_id == NIL
    partner_status = None
    if not is_platform:
        partner = db.get(Partner, partner_id)
        partner_status = partner.status if partner else None

    roles = [m.role for m in db.query(Membership).filter(Membership.user_id == user.id).all()]
    return Principal(user_id=user.id, partner_id=partner_id,
                     is_platform=is_platform, roles=roles, partner_status=partner_status)
