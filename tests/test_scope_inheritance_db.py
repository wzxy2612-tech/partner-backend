"""Ancestry resolution + inheritance decision, end to end under a partner scope."""
from app.services.scopes import resolve_scope_chain, principal_can_access
from app.models.enums import Role, ScopeType


def test_workspace_chain_walks_to_partner_root(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        chain = resolve_scope_chain(db, ScopeType.workspace, ids.workspace_a_child)
    assert chain == [
        (ScopeType.workspace, ids.workspace_a_child),
        (ScopeType.workspace, ids.workspace_a_parent),
        (ScopeType.company, ids.company_a),
        (ScopeType.partner, ids.partner_a),
    ]


def test_company_chain(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        chain = resolve_scope_chain(db, ScopeType.company, ids.company_a)
    assert chain == [(ScopeType.company, ids.company_a), (ScopeType.partner, ids.partner_a)]


def test_partner_super_admin_inherits_to_child_workspace(ids, partner_orm):
    grants = [(Role.partner_super_admin, (ScopeType.partner, ids.partner_a))]
    with partner_orm(ids.partner_a) as db:
        chain = resolve_scope_chain(db, ScopeType.workspace, ids.workspace_a_child)
    assert principal_can_access(grants, chain) is True
