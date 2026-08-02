"""The authenticated principal and how it is resolved.

Authentication runs on the platform path (BYPASSRLS) because it must read the
session/user/partner rows BEFORE any tenant scope exists. The resolved
partner_id then drives which DB path (and RLS scope) the request runs under --
the client never supplies it.

A principal carries not just its roles but the *scope* each role was granted at
(`grants`), so RBAC can enforce both "has this permission" and "at a scope that
reaches the target".
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
from app.models.enums import Role, ScopeType, PartnerStatus

NIL = UUID("00000000-0000-0000-0000-000000000000")

# (role, (scope_type, scope_id)) -- one entry per membership.
Grant = tuple[Role, tuple[ScopeType, UUID]]


@dataclass
class Principal:
    """Two facts that used to be one field, and must never be conflated again.

    ``is_platform_path`` is a ROUTING fact: this principal has no tenant, so its
    queries run on the bypass connection instead of the RLS-scoped one. Every
    direct (Stripe) customer is on the platform path.

    ``is_platform_admin`` is an AUTHORIZATION fact: this principal may operate
    the platform -- suspend partners, deactivate by domain, run cross-tenant
    retention jobs. It is derived from a granted role and nothing else.

    Collapsing these into one boolean is what made every direct customer a
    platform operator (they share the nil-UUID tenant, which is the routing
    fact, not the authorization one). The nil sentinel is a fine simplification
    in the DATA layer; it must not leak into the AUTHORIZATION layer.
    """
    user_id: UUID
    partner_id: UUID
    is_platform_path: bool
    roles: list[Role] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    partner_status: PartnerStatus | None = None

    @property
    def is_platform_admin(self) -> bool:
        """Platform operator privileges.

        Requires a platform_super_admin grant that is ALSO anchored to the
        platform tuple: partner NIL, scope_type platform. 0010 enforces that
        anchoring as a DB CHECK, so a well-formed database cannot produce a
        partner-scoped platform_super_admin -- but the role label alone was the
        thing a forged membership abused, so the authorization check verifies
        the whole tuple rather than trusting the label. Absence of a tenant was
        never evidence of privilege; neither is a role name on its own.
        """
        return any(
            role == Role.platform_super_admin
            and scope_type == ScopeType.platform
            and self.partner_id == NIL
            for role, (scope_type, _scope_id) in self.grants
        )

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
    # Routing only: no tenant -> platform DB path. Says nothing about privilege.
    is_platform_path = partner_id == NIL
    partner_status = None
    if not is_platform_path:
        partner = db.get(Partner, partner_id)
        partner_status = partner.status if partner else None

    # A session must belong to the same tenant as its user. These are separate
    # columns with separate constraints, so a row could disagree; if it does,
    # refuse rather than trusting either side. 0007 makes this unreachable via
    # a composite FK -- this check is the fail-closed backstop for rows that
    # predate it, and it is cheap.
    if row.partner_id != user.partner_id:
        return None

    memberships = db.query(Membership).filter(Membership.user_id == user.id).all()
    roles = [m.role for m in memberships]
    grants: list[Grant] = [(m.role, (m.scope_type, m.scope_id)) for m in memberships]
    return Principal(user_id=user.id, partner_id=partner_id, is_platform_path=is_platform_path,
                     roles=roles, grants=grants, partner_status=partner_status)
