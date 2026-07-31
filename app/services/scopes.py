"""Scope inheritance: a role granted at a higher scope covers everything beneath
it. A partner-scoped Partner Super Admin covers all the partner's companies and
workspaces; a platform super admin covers everything.

The *rule* is a pure function (unit-testable). Building a target's ancestry chain
needs the DB and runs under the partner's RLS scope.
"""
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.enums import Role, ScopeType

# A node in a scope chain, e.g. (ScopeType.company, <company_id>).
ScopeNode = tuple[ScopeType, UUID]


def membership_covers(membership_scope: ScopeNode, target_chain: list[ScopeNode]) -> bool:
    """True if a membership granted at ``membership_scope`` reaches a target whose
    ancestry (most specific -> partner root) is ``target_chain``."""
    return membership_scope in target_chain


def principal_can_access(roles_at_scopes: list[tuple[Role, ScopeNode]],
                         target_chain: list[ScopeNode]) -> bool:
    """Given a principal's (role, scope) grants, decide access to a target scope."""
    for role, scope in roles_at_scopes:
        if role == Role.platform_super_admin:
            return True
        if membership_covers(scope, target_chain):
            return True
    return False


def resolve_scope_chain(db: OrmSession, scope_type: ScopeType, scope_id: UUID) -> list[ScopeNode]:
    """Ancestry of a scope, most specific first, ending at (partner, partner_id).
    Runs under the caller's RLS scope, so it can only ever walk the caller's own
    tree."""
    chain: list[ScopeNode] = []

    if scope_type == ScopeType.workspace:
        current: UUID | None = scope_id
        company_id = None
        partner_id = None
        # Walk parent_workspace_id up to the root of the tree.
        while current is not None:
            row = db.execute(
                text("SELECT parent_workspace_id, company_id, partner_id "
                     "FROM workspaces WHERE id = :id"),
                {"id": str(current)},
            ).first()
            if row is None:
                break
            chain.append((ScopeType.workspace, current))
            company_id, partner_id = row.company_id, row.partner_id
            current = row.parent_workspace_id
        if company_id is not None:
            chain.append((ScopeType.company, company_id))
        if partner_id is not None:
            chain.append((ScopeType.partner, partner_id))
        return chain

    if scope_type == ScopeType.company:
        row = db.execute(
            text("SELECT partner_id FROM companies WHERE id = :id"),
            {"id": str(scope_id)},
        ).first()
        chain.append((ScopeType.company, scope_id))
        if row is not None:
            chain.append((ScopeType.partner, row.partner_id))
        return chain

    # partner (or platform) scope: it is its own root.
    chain.append((scope_type, scope_id))
    return chain
