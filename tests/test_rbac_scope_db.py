"""RBAC end to end: real grants (from authenticate) x real scope chains (RLS)."""
from app.auth.sessions import issue_session
from app.auth.principal import authenticate
from app.services.rbac import Permission, principal_can
from app.services.scopes import resolve_scope_chain
from app.models.enums import Role, ScopeType


def _principal_for(db, user_id, partner_id):
    return authenticate(db, issue_session(db, user_id=user_id, partner_id=partner_id))


def test_company_admin_grant_is_scoped_to_its_company(ids, platform_orm):
    with platform_orm() as db:
        p = _principal_for(db, ids.user_ca, ids.partner_a)
    assert p.is_platform_path is False
    assert (Role.company_admin, (ScopeType.company, ids.company_a)) in p.grants


def test_company_admin_manages_own_company_not_sibling(ids, platform_orm, partner_orm):
    with platform_orm() as db:
        p = _principal_for(db, ids.user_ca, ids.partner_a)
    with partner_orm(ids.partner_a) as db:
        chain_own = resolve_scope_chain(db, ScopeType.workspace, ids.workspace_a_child)
        chain_sibling = resolve_scope_chain(db, ScopeType.company, ids.company_a2)
    assert principal_can(p.grants, Permission.manage_workspaces, chain_own) is True
    assert principal_can(p.grants, Permission.manage_workspaces, chain_sibling) is False


def test_read_only_can_view_not_write(ids, platform_orm, partner_orm):
    with platform_orm() as db:
        p = _principal_for(db, ids.user_ro, ids.partner_a)
    with partner_orm(ids.partner_a) as db:
        chain = resolve_scope_chain(db, ScopeType.workspace, ids.workspace_a_child)
    assert principal_can(p.grants, Permission.view, chain) is True
    assert principal_can(p.grants, Permission.manage_workspaces, chain) is False
