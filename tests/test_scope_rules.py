"""Pure tests for the scope-inheritance rule -- no DB."""
from uuid import uuid4

from app.services.scopes import membership_covers, principal_can_access
from app.models.enums import Role, ScopeType

PARTNER = uuid4()
COMPANY = uuid4()
WORKSPACE = uuid4()

# Ancestry of a workspace: most specific -> partner root.
CHAIN = [
    (ScopeType.workspace, WORKSPACE),
    (ScopeType.company, COMPANY),
    (ScopeType.partner, PARTNER),
]


def test_partner_scope_covers_child_workspace():
    assert membership_covers((ScopeType.partner, PARTNER), CHAIN)


def test_company_scope_covers_its_workspace():
    assert membership_covers((ScopeType.company, COMPANY), CHAIN)


def test_unrelated_partner_scope_does_not_cover():
    assert not membership_covers((ScopeType.partner, uuid4()), CHAIN)


def test_platform_super_admin_covers_everything():
    grants = [(Role.platform_super_admin, (ScopeType.platform, uuid4()))]
    assert principal_can_access(grants, CHAIN)


def test_partner_super_admin_reaches_workspace():
    grants = [(Role.partner_super_admin, (ScopeType.partner, PARTNER))]
    assert principal_can_access(grants, CHAIN)


def test_no_covering_grant_is_denied():
    grants = [(Role.company_admin, (ScopeType.company, uuid4()))]
    assert not principal_can_access(grants, CHAIN)
