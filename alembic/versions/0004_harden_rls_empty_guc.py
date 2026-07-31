"""harden RLS policies against an empty-string tenant GUC"""
from alembic import op
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None
GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"
OLD = "current_setting('app.partner_id', true)::uuid"
PARTNER_ID_POLICIES = [
    ("companies", "partner_isolation", "partner_id"),
    ("memberships", "partner_isolation", "partner_id"),
    ("partner_activity_log", "partner_isolation", "partner_id"),
    ("workspaces", "partner_isolation", "partner_id"),
    ("users", "partner_isolation", "partner_id"),
    ("sessions", "partner_isolation", "partner_id"),
]
def _recreate(table, policy, col, expr):
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
    op.execute(f"CREATE POLICY {policy} ON {table} "
               f"USING ({col} = {expr}) WITH CHECK ({col} = {expr})")
def upgrade():
    for t, p, c in PARTNER_ID_POLICIES:
        _recreate(t, p, c, GUC)
    _recreate("partners", "partner_self_isolation", "id", GUC)
def downgrade():
    for t, p, c in PARTNER_ID_POLICIES:
        _recreate(t, p, c, OLD)
    _recreate("partners", "partner_self_isolation", "id", OLD)
