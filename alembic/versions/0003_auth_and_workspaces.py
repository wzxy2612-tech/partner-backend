"""auth sessions + workspace parent/child tree

Phase 2 structural additions:
  * `sessions` -- server-side session store so tokens are revocable. Auth runs
    BEFORE tenant scope is known, so this table is read on the platform path.
    RLS is ENABLED (not FORCED) keyed on partner_id as defense-in-depth: the
    platform role bypasses it, but a stray runtime query would still be scoped.
  * `workspaces` -- company-scoped, self-referential parent/child tree
    (parent_workspace_id). Partner-owned, so RLS ENABLED + FORCED keyed on
    partner_id, identical to the other partner tables from 0002.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- sessions: revocable server-side sessions (platform-path auth) ----
    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        # partner scope captured at login time; nil sentinel for platform/direct.
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text("'00000000-0000-0000-0000-000000000000'::uuid")),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_partner_id", "sessions", ["partner_id"])

    # --- workspaces: company-scoped parent/child tree --------------------
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("company_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("parent_workspace_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        # NULL branding keys -> inherit from parent hub / company (resolved in code).
        sa.Column("branding", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_foreign_key(
        "fk_workspaces_parent", "workspaces", "workspaces",
        ["parent_workspace_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_workspaces_partner_id", "workspaces", ["partner_id"])
    op.create_index("ix_workspaces_company_id", "workspaces", ["company_id"])
    op.create_index("ix_workspaces_parent_id", "workspaces", ["parent_workspace_id"])

    # --- RLS --------------------------------------------------------------
    # workspaces: partner-owned -> ENABLE + FORCE, same policy shape as 0002.
    op.execute("ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE workspaces FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY partner_isolation ON workspaces "
        "USING (partner_id = current_setting('app.partner_id', true)::uuid) "
        "WITH CHECK (partner_id = current_setting('app.partner_id', true)::uuid)"
    )

    # sessions: ENABLE (not FORCE) -> platform bypasses; stray runtime is scoped.
    op.execute("ALTER TABLE sessions ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY partner_isolation ON sessions "
        "USING (partner_id = current_setting('app.partner_id', true)::uuid) "
        "WITH CHECK (partner_id = current_setting('app.partner_id', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS partner_isolation ON sessions")
    op.execute("DROP POLICY IF EXISTS partner_isolation ON workspaces")

    op.drop_index("ix_workspaces_parent_id", table_name="workspaces")
    op.drop_index("ix_workspaces_company_id", table_name="workspaces")
    op.drop_index("ix_workspaces_partner_id", table_name="workspaces")
    op.drop_constraint("fk_workspaces_parent", "workspaces", type_="foreignkey")
    op.drop_table("workspaces")

    op.drop_index("ix_sessions_partner_id", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
