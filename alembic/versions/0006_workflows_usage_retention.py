"""workflows, connectors, token usage, and retention/archival scaffolding

Phase 5 tables, all partner-owned -> RLS ENABLE + FORCE keyed on partner_id
(hardened NULLIF form):
  * connectors          -- per-partner integrations with a verified status
  * workflow_templates  -- parent-hub templates, each declaring required connectors
  * workflows           -- instances cloned from a template into a company
  * token_usage         -- monthly per-partner token counter (upsert)
  * threads             -- chat threads, for the 1-year archival sweep
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

GUC = "NULLIF(current_setting('app.partner_id', true), '')::uuid"
PARTNER_TABLES = ["connectors", "workflow_templates", "workflows", "token_usage", "threads"]


def upgrade() -> None:
    op.create_table(
        "connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="unverified"),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("partner_id", "kind", name="uq_connector_partner_kind"),
    )
    op.create_index("ix_connectors_partner_id", "connectors", ["partner_id"])

    op.create_table(
        "workflow_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("definition", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("required_connectors", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_workflow_templates_partner_id", "workflow_templates", ["partner_id"])

    op.create_table(
        "workflows",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("company_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("workflow_templates.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("definition", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_workflows_partner_id", "workflows", ["partner_id"])
    op.create_index("ix_workflows_company_id", "workflows", ["company_id"])

    op.create_table(
        "token_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),  # 'YYYY-MM'
        sa.Column("tokens", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("partner_id", "period", name="uq_usage_partner_period"),
    )
    op.create_index("ix_token_usage_partner_id", "token_usage", ["partner_id"])

    op.create_table(
        "threads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("partners.id", ondelete="CASCADE"), nullable=False),
        sa.Column("company_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_threads_partner_created", "threads", ["partner_id", "created_at"])

    for table in PARTNER_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY partner_isolation ON {table} "
            f"USING (partner_id = {GUC}) WITH CHECK (partner_id = {GUC})")


def downgrade() -> None:
    for table in PARTNER_TABLES:
        op.execute(f"DROP POLICY IF EXISTS partner_isolation ON {table}")
    op.drop_table("threads")
    op.drop_table("token_usage")
    op.drop_table("workflows")
    op.drop_table("workflow_templates")
    op.drop_table("connectors")
