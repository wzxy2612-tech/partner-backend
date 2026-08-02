"""workspace parent must be in the same company, enforced by the database

Audit #11. 0007 made the workspace parent FK tenant-composite, so a parent in
another PARTNER became impossible. It did not constrain COMPANY, and inside one
partner that gap is an authorization bypass:

    resolve_scope_chain() walks parent_workspace_id upward and reassigns
    company_id on every iteration, so the chain it returns carries the ROOT's
    company, not the target's. Hang a Company A workspace under a Company A2
    parent and a Company A2 admin passes manage_workspaces on a workspace that
    belongs to Company A -- and inherits A2's branding into it.

0011's round added the service-layer check in create_workspace(), which is the
friendly 400. This is the adjudicator. A service check binds only the code paths
that remember to call it; an import script, a background job, an ORM write or a
new endpoint that forgets reopens the hole silently. The company boundary is a
business invariant, so it belongs where invariants cannot be skipped.

    child(parent_workspace_id, partner_id, company_id)
        -> parent(id, partner_id, company_id)

MATCH SIMPLE still does the right thing for roots: parent_workspace_id IS NULL
means "no reference" and the constraint is not checked. partner_id and
company_id are both NOT NULL, so no other column can silently disable it.

EXISTING DATA IS NOT REPAIRED HERE. The preflight lists every offending row and
refuses. A cross-company parent link is both a permission-boundary problem and a
topology problem: silently NULLing the parent would change hierarchy, branding
inheritance and possibly business meaning, and doing that inside a migration
takes the decision away from the only person who can make it. Each row needs an
explicit choice -- reattach to a legitimate same-company parent, detach to a
root, or re-home the workspace. See scripts/scan_cross_company_parents.sql for a
read-only pre-scan to run BEFORE attempting the migration.

If a shared parent hub across companies is ever a real product requirement, it
should be modelled explicitly (an organization-level hub with its own
permission and inheritance rules), not by relaxing this edge.
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

OLD_PARENT_FK = "fk_workspaces_parent_workspace_id_partner"
NEW_PARENT_FK = "fk_workspaces_parent_partner_company"
NEW_UNIQUE = "uq_workspaces_id_partner_company"


def upgrade() -> None:
    conn = op.get_bind()

    # --- preflight: refuse, and name every offending row ------------------
    offenders = conn.execute(sa.text("""
        SELECT c.id            AS child_workspace_id,
               c.company_id    AS child_company_id,
               p.id            AS parent_workspace_id,
               p.company_id    AS parent_company_id,
               c.partner_id    AS partner_id
        FROM workspaces c
        JOIN workspaces p ON p.id = c.parent_workspace_id
        WHERE c.company_id IS DISTINCT FROM p.company_id
        ORDER BY c.partner_id, c.id
    """)).all()

    if offenders:
        rows = "\n  ".join(
            f"child={r.child_workspace_id} (company {r.child_company_id}) -> "
            f"parent={r.parent_workspace_id} (company {r.parent_company_id}) "
            f"partner={r.partner_id}"
            for r in offenders)
        raise RuntimeError(
            f"0012 preflight: {len(offenders)} workspace parent link(s) cross a "
            f"company boundary inside one partner. Each is an authorization "
            f"bypass -- scope resolution reports the ROOT's company, so an admin "
            f"of the parent's company reaches the child.\n\n"
            f"This migration will not repair them: detaching or re-homing a "
            f"workspace changes hierarchy and branding inheritance, and that "
            f"decision is not a migration's to make. For each row, reattach to a "
            f"same-company parent, detach it to a root, or re-home the "
            f"workspace, then re-run.\n\n  {rows}")

    # --- the referenced key, now including company ------------------------
    op.create_unique_constraint(
        NEW_UNIQUE, "workspaces", ["id", "partner_id", "company_id"])

    # --- replace the two-column parent FK with the three-column one -------
    # uq_workspaces_id_partner is deliberately KEPT: 0007 created it and this
    # migration does not know that nothing else will ever reference it. Dropping
    # a unique key that another FK targets would fail loudly, but leaving an
    # unused one costs only an index.
    op.execute(f'ALTER TABLE workspaces DROP CONSTRAINT "{OLD_PARENT_FK}"')
    op.execute(
        f'ALTER TABLE workspaces ADD CONSTRAINT "{NEW_PARENT_FK}" '
        f'FOREIGN KEY (parent_workspace_id, partner_id, company_id) '
        f'REFERENCES workspaces (id, partner_id, company_id) '
        f'ON DELETE SET NULL (parent_workspace_id)')


def downgrade() -> None:
    op.execute(f'ALTER TABLE workspaces DROP CONSTRAINT "{NEW_PARENT_FK}"')
    op.execute(
        f'ALTER TABLE workspaces ADD CONSTRAINT "{OLD_PARENT_FK}" '
        f'FOREIGN KEY (parent_workspace_id, partner_id) '
        f'REFERENCES workspaces (id, partner_id) '
        f'ON DELETE SET NULL (parent_workspace_id)')
    op.drop_constraint(NEW_UNIQUE, "workspaces", type_="unique")
