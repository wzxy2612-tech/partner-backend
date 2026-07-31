"""partner multi-tenancy + row-level security

Adds the partner tenancy model on top of the direct-customer baseline and
enforces tenant isolation in the database via RLS.

Key decisions encoded here:
  * New partner-owned tables get RLS ENABLED and FORCED -> fail closed. Even the
    table owner, and any query with no tenant context set, sees zero rows.
  * The pre-existing `users` table gets partner columns with safe defaults and
    RLS ENABLED but NOT FORCED, so the direct-customer / Stripe path (which runs
    as app_platform, BYPASSRLS) is completely unchanged.
  * Every policy keys on a server-set GUC `app.partner_id`. Missing GUC ->
    current_setting(..., true) returns NULL -> comparison is NULL -> no rows.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

NIL = "00000000-0000-0000-0000-000000000000"  # sentinel partner_id for platform/direct rows

FORCED_TABLES = [
    ("companies", "partner_id"),
    ("memberships", "partner_id"),
    ("partner_activity_log", "partner_id"),
]


def upgrade() -> None:
    # --- enum types -------------------------------------------------------
    op.execute("CREATE TYPE partner_status AS ENUM ('active','suspended')")
    op.execute("CREATE TYPE billing_source AS ENUM ('stripe','partner')")
    op.execute("CREATE TYPE app_role AS ENUM "
               "('platform_super_admin','partner_super_admin','company_admin','author','read_only')")
    op.execute("CREATE TYPE scope_type AS ENUM ('platform','partner','company','workspace')")

    # --- partners: the tenant root ---------------------------------------
    op.create_table(
        "partners",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", postgresql.ENUM(name="partner_status", create_type=False),
                  nullable=False, server_default="active"),
        sa.Column("billing_contact_email", sa.String(320), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspension_retention_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    # --- companies: partner-scoped ---------------------------------------
    op.create_table(
        "companies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("branding", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_companies_partner_id", "companies", ["partner_id"])

    # --- memberships: partner-scoped RBAC bindings -----------------------
    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope_type", postgresql.ENUM(name="scope_type", create_type=False), nullable=False),
        sa.Column("scope_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("role", postgresql.ENUM(name="app_role", create_type=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("user_id", "scope_type", "scope_id", "role", name="uq_membership"),
    )
    op.create_index("ix_memberships_partner_id", "memberships", ["partner_id"])

    # --- partner activity log: partner-scoped ----------------------------
    op.create_table(
        "partner_activity_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.execute("CREATE INDEX ix_activity_partner_created "
               "ON partner_activity_log (partner_id, created_at DESC)")
    op.execute("CREATE INDEX ix_activity_partner_event_created "
               "ON partner_activity_log (partner_id, event_type, created_at DESC)")

    # --- extend the pre-existing users table (backward compatible) -------
    op.add_column("users", sa.Column(
        "partner_id", postgresql.UUID(as_uuid=True), nullable=False,
        server_default=sa.text(f"'{NIL}'::uuid")))
    op.add_column("users", sa.Column(
        "billing_source", postgresql.ENUM(name="billing_source", create_type=False),
        nullable=False, server_default="stripe"))
    op.add_column("users", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_partner_id", "users", ["partner_id"])

    # --- Row-Level Security ----------------------------------------------
    for table, col in FORCED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY partner_isolation ON {table} "
            f"USING ({col} = current_setting('app.partner_id', true)::uuid) "
            f"WITH CHECK ({col} = current_setting('app.partner_id', true)::uuid)"
        )

    # partners: a partner may see only its own row (keyed on id).
    op.execute("ALTER TABLE partners ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE partners FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY partner_self_isolation ON partners "
        "USING (id = current_setting('app.partner_id', true)::uuid) "
        "WITH CHECK (id = current_setting('app.partner_id', true)::uuid)"
    )

    # users: PRE-EXISTING. ENABLE but do NOT FORCE, so app_platform (BYPASSRLS)
    # -- the direct-customer / Stripe path -- is unchanged.
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY partner_isolation ON users "
        "USING (partner_id = current_setting('app.partner_id', true)::uuid) "
        "WITH CHECK (partner_id = current_setting('app.partner_id', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS partner_isolation ON users")
    op.execute("DROP POLICY IF EXISTS partner_self_isolation ON partners")
    for table, _ in FORCED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS partner_isolation ON {table}")

    op.drop_index("ix_users_partner_id", table_name="users")
    op.drop_column("users", "archived_at")
    op.drop_column("users", "billing_source")
    op.drop_column("users", "partner_id")

    op.execute("DROP INDEX IF EXISTS ix_activity_partner_event_created")
    op.execute("DROP INDEX IF EXISTS ix_activity_partner_created")
    op.drop_table("partner_activity_log")
    op.drop_index("ix_memberships_partner_id", table_name="memberships")
    op.drop_table("memberships")
    op.drop_index("ix_companies_partner_id", table_name="companies")
    op.drop_table("companies")
    op.drop_table("partners")

    op.execute("DROP TYPE IF EXISTS scope_type")
    op.execute("DROP TYPE IF EXISTS app_role")
    op.execute("DROP TYPE IF EXISTS billing_source")
    op.execute("DROP TYPE IF EXISTS partner_status")
