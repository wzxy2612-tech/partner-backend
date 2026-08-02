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

# Hard ceiling on any parent-chain walk.
#
# Validating at write time that a new parent introduces no cycle is fail-OPEN:
# it holds only as long as every present and future write path remembers to
# call it, and one that forgets produces a chain that never terminates -- inside
# the authorization path, on every request. This cap is the fail-CLOSED half. It
# does not care how a cycle arrived; it refuses to loop.
#
# 32 is far past any real hub nesting, so hitting it means the data is wrong.
MAX_SCOPE_DEPTH = 32


class CrossCompanyParent(RuntimeError):
    """A workspace parent chain crosses a company boundary.

    Impossible to create once 0012 is applied; this is the runtime backstop for
    rows that predate it. Fail closed rather than resolving the caller against
    a company the target does not belong to."""


class ScopeChainTooDeep(RuntimeError):
    """A parent chain exceeded MAX_SCOPE_DEPTH -- almost certainly a cycle."""


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
        # Pinned on the FIRST row read and never reassigned. The walk used to
        # overwrite company_id on every iteration, so the chain ended up
        # carrying the ROOT ancestor's company instead of the target's -- which
        # is how a Company A2 admin passed authorization on a Company A
        # workspace hung under an A2 parent. The company a workspace belongs to
        # is a property of that workspace, not of wherever its chain happens to
        # terminate.
        target_company_id: UUID | None = None
        partner_id = None
        seen: set[UUID] = set()
        # Walk parent_workspace_id up to the root of the tree.
        while current is not None:
            if current in seen or len(seen) >= MAX_SCOPE_DEPTH:
                raise ScopeChainTooDeep(
                    f"workspace parent chain from {scope_id} cycles or exceeds "
                    f"{MAX_SCOPE_DEPTH}; refusing to resolve authorization scope")
            seen.add(current)
            row = db.execute(
                text("SELECT parent_workspace_id, company_id, partner_id "
                     "FROM workspaces WHERE id = :id"),
                {"id": str(current)},
            ).first()
            if row is None:
                break
            chain.append((ScopeType.workspace, current))
            if target_company_id is None:
                target_company_id = row.company_id      # first row only
            elif row.company_id != target_company_id:
                # 0012 makes this unreachable via the schema. Reaching it means
                # data predating that constraint, and continuing would resolve
                # the caller against another company -- fail closed instead.
                raise CrossCompanyParent(
                    f"workspace {current} is in company {row.company_id} but "
                    f"the chain from {scope_id} started in {target_company_id}")
            partner_id = row.partner_id
            current = row.parent_workspace_id
        if target_company_id is not None:
            chain.append((ScopeType.company, target_company_id))
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
