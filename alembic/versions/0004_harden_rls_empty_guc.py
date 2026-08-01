"""harden RLS policies against an empty-string tenant GUC

The 0002/0003 policies compared against
    current_setting('app.partner_id', true)::uuid
which assumes the GUC is either a valid UUID or NULL. But on a POOLED connection
that previously ran ``SET LOCAL app.partner_id = '...'``, the reset value of a
custom GUC is the empty string '' (not "unset"), and ''::uuid raises
InvalidTextRepresentation. That turned "no tenant context" from a clean
zero-rows result into a hard error.

This migration recreates every policy using
    NULLIF(current_setting('app.partner_id', true), '')::uuid
so that BOTH NULL and '' collapse to NULL -> the equality is NULL -> no rows.
Fail-closed, without the error.

Only the USING/WITH CHECK expressions change; ENABLE / FORCE state is untouched.
On a fresh database this runs harmlessly after 0002/0003; on an already-migrated
database it patches the policies in place (no data reset needed).
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"
OLD = "current_setting('app.partner_id', true)::uuid"

# (table, policy_name, key_column)
PARTNER_ID_POLICIES = [
    ("companies", "partner_isolation", "partner_id"),
    ("memberships", "partner_isolation", "partner_id"),
    ("partner_activity_log", "partner_isolation", "partner_id"),
    ("workspaces", "partner_isolation", "partner_id"),
    ("users", "partner_isolation", "partner_id"),
    ("sessions", "partner_isolation", "partner_id"),
]


def _recreate(table: str, policy: str, col: str, expr: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
    op.execute(
        f"CREATE POLICY {policy} ON {table} "
        f"USING ({col} = {expr}) WITH CHECK ({col} = {expr})"
    )


def upgrade() -> None:
    for table, policy, col in PARTNER_ID_POLICIES:
        _recreate(table, policy, col, GUC)
    # partners keys on its own id.
    _recreate("partners", "partner_self_isolation", "id", GUC)


def downgrade() -> None:
    for table, policy, col in PARTNER_ID_POLICIES:
        _recreate(table, policy, col, OLD)
    _recreate("partners", "partner_self_isolation", "id", OLD)
