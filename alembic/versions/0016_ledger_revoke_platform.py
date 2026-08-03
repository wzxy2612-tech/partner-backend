"""Finish the revoke 0014 only half did.

0014 took the migration ledger away from app_runtime and stopped there. But
`ALTER DEFAULT PRIVILEGES` (db/init/00-roles.sql:35) grants every new table to
app_runtime AND app_platform, so alembic_version was granted to both and revoked
from one.

That is the recurring shape in this project: the forbidden side written for one
subject and not for the others it is equally forbidden to. Here it is worse than
usual, because app_platform is BYPASSRLS -- row security was never going to stop
it, so the grant was the only control and it was left in place.

Why it matters at all: `alembic check` is one of this project's three release
gates and its ground truth is the row in alembic_version. A gate whose evidence
can be rewritten by the code it constrains is not a gate.

The root cause is untouched and deliberately so. Default privileges still make
every new table reachable by both application roles the moment it is created;
what changed is that tests/test_rls_coverage.py now enumerates from privileges
per role, so the next table lands with one test run of latency rather than two
audit rounds. Closing the window itself means CI, not schema.
"""
import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

BOOKKEEPING = "alembic_version"
ROLE = "app_platform"


def upgrade() -> None:
    conn = op.get_bind()

    op.execute(f"REVOKE ALL ON {BOOKKEEPING} FROM {ROLE}")

    # has_any_column_privilege, not has_table_privilege: a table-level REVOKE
    # does not remove column-level grants in PostgreSQL, and the table-level
    # function cannot see them. Same predicate the coverage guard uses, so the
    # two cannot disagree about what "can reach" means.
    still_held = conn.execute(sa.text("""
        SELECT has_any_column_privilege(:role, :t, 'SELECT')
            OR has_any_column_privilege(:role, :t, 'INSERT')
            OR has_any_column_privilege(:role, :t, 'UPDATE')
            OR has_table_privilege     (:role, :t, 'DELETE')
    """), {"role": ROLE, "t": BOOKKEEPING}).scalar_one()
    if still_held:
        raise RuntimeError(
            f"0016 postflight: {ROLE} can still reach {BOOKKEEPING} after "
            f"REVOKE ALL. Check for column-level grants.")


def downgrade() -> None:
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {BOOKKEEPING} TO {ROLE}")
