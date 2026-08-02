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


# --- cycle / depth backstop (audit #5) --------------------------------------

def test_depth_cap_is_below_python_recursion_and_above_real_nesting():
    """The cap has to sit in a specific window: high enough that no legitimate
    hub tree reaches it, low enough that a cycle is caught long before the walk
    becomes a request-time hang."""
    from app.services.scopes import MAX_SCOPE_DEPTH
    assert 8 <= MAX_SCOPE_DEPTH <= 128


def test_both_parent_walks_share_one_cap():
    """Scope resolution and branding resolution follow the SAME parent chain.
    Two separate limits would be two answers to one question and would drift;
    branding imports the constant rather than redefining it."""
    import inspect
    from app.services import workspaces, scopes
    src = inspect.getsource(workspaces.resolve_branding)
    assert "MAX_SCOPE_DEPTH" in src
    assert workspaces.MAX_SCOPE_DEPTH is scopes.MAX_SCOPE_DEPTH
