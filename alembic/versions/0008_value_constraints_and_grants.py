"""value constraints, and closing app_runtime's reach into direct-customer data

Three unrelated-looking items with one thing in common: the database was
accepting states that no correct caller would produce, and relying on callers
to not produce them.

1. token_usage accepted a negative token count and an impossible period
   (audit #14). `record_usage(..., -25, "2026-99")` was stored verbatim.

2. subscriptions has no RLS and no partner_id -- it predates tenancy and belongs
   to the direct-customer Stripe path. But db/init/00-roles.sql grants app_owner's
   default privileges on EVERY table to app_runtime, so the partner request path
   inherited full DML on direct customers' billing rows.

   This is the reverse direction from every isolation test in the suite. All ten
   negative tests ask "can partner A reach partner B" -- none asks "can a partner
   reach the direct customers", so a table with no tenant column at all was
   outside what they could see.

   Fixed by revoking rather than by adding a policy: a subscription's tenant
   would have to be derived by joining users, which makes the policy a second
   place where "who owns this row" gets decided. app_runtime has no legitimate
   reason to touch this table, so the honest fix is to take the grant away.

3. stripe_subscription_id had no unique constraint, so two rows could claim the
   same Stripe subscription and webhook replay had no single row to converge on.
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

# Tables the partner runtime path must never touch. Anything without a
# partner_id column is, by construction, not partner-scoped.
PLATFORM_ONLY_TABLES = ["subscriptions"]


def upgrade() -> None:
    conn = op.get_bind()

    # --- 1. token_usage value constraints ---------------------------------
    bad = conn.execute(sa.text(
        "SELECT count(*) FROM token_usage "
        "WHERE tokens < 0 OR period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$'")).scalar_one()
    if bad:
        raise RuntimeError(
            f"0008 preflight: {bad} token_usage row(s) already violate the "
            f"constraints being added (negative tokens or an impossible "
            f"period). Correct them before migrating -- silently deleting "
            f"billing data is not this migration's call to make.")

    op.create_check_constraint("ck_token_usage_tokens_nonneg", "token_usage", "tokens >= 0")
    op.create_check_constraint(
        "ck_token_usage_period_format", "token_usage",
        "period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'")

    # --- 2. stripe_subscription_id uniqueness ------------------------------
    dupes = conn.execute(sa.text(
        "SELECT count(*) FROM (SELECT stripe_subscription_id FROM subscriptions "
        "WHERE stripe_subscription_id IS NOT NULL "
        "GROUP BY stripe_subscription_id HAVING count(*) > 1) d")).scalar_one()
    if dupes:
        raise RuntimeError(
            f"0008 preflight: {dupes} stripe_subscription_id value(s) appear on "
            f"more than one row. Reconcile against Stripe before adding the "
            f"unique constraint.")

    # Partial: NULL means "not yet linked", and many rows may be unlinked.
    op.execute("CREATE UNIQUE INDEX uq_subscriptions_stripe_id "
               "ON subscriptions (stripe_subscription_id) "
               "WHERE stripe_subscription_id IS NOT NULL")

    # --- 3. revoke the partner runtime path from platform-only tables ------
    for table in PLATFORM_ONLY_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM app_runtime")


def downgrade() -> None:
    for table in PLATFORM_ONLY_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_runtime")
    op.execute("DROP INDEX IF EXISTS uq_subscriptions_stripe_id")
    op.drop_constraint("ck_token_usage_period_format", "token_usage", type_="check")
    op.drop_constraint("ck_token_usage_tokens_nonneg", "token_usage", type_="check")
