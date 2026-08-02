"""Pure RBAC: role->permission table and the role x scope decision. No DB."""
from uuid import uuid4

from app.services.rbac import Permission, principal_can, role_has
from app.models.enums import Role, ScopeType

PARTNER, COMPANY, COMPANY2, WS = uuid4(), uuid4(), uuid4(), uuid4()
CHAIN_WS = [(ScopeType.workspace, WS), (ScopeType.company, COMPANY), (ScopeType.partner, PARTNER)]


def test_role_permission_table():
    assert role_has(Role.read_only, Permission.view)
    assert not role_has(Role.read_only, Permission.manage_workspaces)
    assert role_has(Role.company_admin, Permission.manage_workspaces)
    assert not role_has(Role.author, Permission.manage_users)
    assert role_has(Role.partner_super_admin, Permission.manage_billing)


def test_company_admin_manages_within_its_company():
    grants = [(Role.company_admin, (ScopeType.company, COMPANY))]
    assert principal_can(grants, Permission.manage_workspaces, CHAIN_WS)


def test_company_admin_cannot_reach_sibling_company():
    grants = [(Role.company_admin, (ScopeType.company, COMPANY2))]
    assert not principal_can(grants, Permission.manage_workspaces, CHAIN_WS)


def test_read_only_can_view_but_not_write():
    grants = [(Role.read_only, (ScopeType.company, COMPANY))]
    assert principal_can(grants, Permission.view, CHAIN_WS)
    assert not principal_can(grants, Permission.manage_workspaces, CHAIN_WS)


def test_partner_super_admin_reaches_everything_in_partner():
    grants = [(Role.partner_super_admin, (ScopeType.partner, PARTNER))]
    assert principal_can(grants, Permission.manage_users, CHAIN_WS)


def test_platform_super_admin_grant_bypasses_scope():
    """A REAL platform grant reaches any target. Previously this asserted that
    an empty grant list plus an `is_platform=True` flag was allowed -- which is
    what let every tenant-less (direct) customer pass every check."""
    grants = [(Role.platform_super_admin, (ScopeType.platform, None))]
    assert principal_can(grants, Permission.manage_companies, CHAIN_WS)


def test_no_grants_is_denied_even_without_a_tenant():
    """Regression guard for the collapsed flag: having no tenant is not a
    privilege. There is no longer any argument to principal_can that can turn
    an empty grant list into an allow."""
    assert not principal_can([], Permission.manage_companies, CHAIN_WS)


def test_no_grant_is_denied():
    assert not principal_can([], Permission.view, CHAIN_WS)


def test_partner_scope_actions_are_admin_only():
    """view/manage_billing at PARTNER scope: only a partner-scoped grant reaches
    it, so a Company Admin (company-scoped) is denied -- this is what gates the
    activity log and billing-contact endpoints."""
    partner_chain = [(ScopeType.partner, PARTNER)]
    assert not principal_can([(Role.company_admin, (ScopeType.company, COMPANY))],
                             Permission.view, partner_chain)
    assert principal_can([(Role.partner_super_admin, (ScopeType.partner, PARTNER))],
                         Permission.manage_billing, partner_chain)
