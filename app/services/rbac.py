"""Server-side RBAC. Two independent questions, kept separate:

  1. Does this role grant this permission?      -> ROLE_PERMISSIONS (this file)
  2. Does this grant's scope reach the target?  -> scopes.membership_covers

A principal may act only where BOTH hold. Everything here is pure and
unit-testable; the scope side is resolved against the DB under RLS in deps.enforce.
"""
import enum

from app.models.enums import Role, ScopeType
from app.services.scopes import membership_covers, ScopeNode


class Permission(str, enum.Enum):
    manage_companies = "manage_companies"
    manage_workspaces = "manage_workspaces"
    manage_users = "manage_users"       # invite / onboard / deactivate
    manage_billing = "manage_billing"
    edit_content = "edit_content"
    view = "view"


_ALL = frozenset(Permission)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.platform_super_admin: _ALL,
    Role.partner_super_admin: _ALL,
    Role.company_admin: frozenset({
        Permission.manage_workspaces, Permission.manage_users,
        Permission.edit_content, Permission.view,
    }),
    Role.author: frozenset({Permission.edit_content, Permission.view}),
    Role.read_only: frozenset({Permission.view}),
}

# A principal's grant: a role held at a particular scope node.
Grant = tuple[Role, ScopeNode]


def role_has(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def principal_can(grants: list[Grant], permission: Permission,
                  target_chain: list[ScopeNode]) -> bool:
    """True if any grant both carries ``permission`` and is scoped at or above the
    target (whose ancestry, most specific -> partner root, is ``target_chain``).

    Authorization is decided from GRANTS ONLY. There used to be an
    ``is_platform`` parameter here that returned True unconditionally; callers
    passed the principal's "has no tenant" routing flag into it, so every direct
    customer passed every permission check. A platform operator is still
    allowed everywhere -- but via a real ``platform_super_admin`` grant, checked
    in the loop below, not by lacking a tenant.
    """
    for role, scope in grants:
        if role == Role.platform_super_admin:
            return True
        if role_has(role, permission) and membership_covers(scope, target_chain):
            return True
    return False
