"""tenant-composite foreign keys

Root cause behind audit items #2, #3, #4, #5 and the memberships /
partner_activity_log notes:

    RLS decides "may I see or write THIS row". It does not decide "is the row I
    POINT AT mine". Row visibility is not referential integrity.

PostgreSQL deliberately exempts referential-integrity checks from row security
(so that constraints cannot be subverted by hiding rows). That is correct in
general, and it is exactly why every single-column FK here was a tenant hole:
under partner A's RLS scope, inserting `workflows.company_id = <company of B>`
passes, because the FK trigger looks up company B without RLS and finds it.
The only thing standing between that and a cross-tenant breach was application
code remembering to check -- the adjudicator this codebase argues against.

Fix: every reference that crosses rows inside a tenant becomes a COMPOSITE key
carrying partner_id. `(company_id, partner_id) -> companies(id, partner_id)` is
structurally incapable of pointing across tenants, and it stays enforced in
exactly the paths where RLS is not.

No information leak from the stronger constraint: a violation message can only
name a key whose partner_id is the caller's own, so it reveals nothing about
another tenant's rows.

Safe here because every partner_id in this schema is NOT NULL. PostgreSQL's
default MATCH SIMPLE skips a multi-column FK check entirely when ANY of its
columns is NULL -- a nullable partner_id would make every constraint below
decorative. That is also why the *child* column being NULL is fine and
intended: a NULL parent_workspace_id / template_id / actor_user_id means "no
reference", and there is nothing to constrain.

Not done here (each deliberately deferred):
  * Same-COMPANY parent for workspaces (#5). Same-PARTNER is a schema fact and
    is enforced below; whether a parent hub may live in a sibling company is a
    product decision, so it belongs in the service layer.
  * memberships.scope_id is polymorphic (company or workspace by scope_type) and
    cannot be an FK at all; its tenant check stays in code.
  * users.partner_id / sessions.partner_id still have no FK to partners, because
    the nil sentinel has no row there yet. See 0008.
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


# Parent tables need (id, partner_id) as a unique key to be the target of a
# composite FK. Redundant against the PK on id alone -- PostgreSQL requires a
# unique constraint covering exactly the referenced column list.
PARENT_UNIQUES = [
    ("users", "uq_users_id_partner"),
    ("companies", "uq_companies_id_partner"),
    ("workflow_templates", "uq_workflow_templates_id_partner"),
    ("workspaces", "uq_workspaces_id_partner"),
]

# (child, child_col, parent, on_delete, audit_ref)
#
# on_delete preserves each existing FK's semantics rather than flattening them.
# For SET NULL the target column list is REQUIRED (PostgreSQL 15+): a bare
# `ON DELETE SET NULL` on a composite key would try to null partner_id too,
# which is NOT NULL -- the delete would fail at runtime, months later, in the
# one code path nobody tests.
COMPOSITE_FKS = [
    ("sessions",             "user_id",             "users",              "CASCADE",                            "#4 session/user tenant forgery"),
    ("invitations",          "user_id",             "users",              "CASCADE",                            "#2 cross-tenant password reset"),
    ("memberships",          "user_id",             "users",              "CASCADE",                            "role binding across tenants"),
    ("partner_activity_log", "actor_user_id",       "users",              "SET NULL (actor_user_id)",           "audit actor across tenants"),
    ("workspaces",           "company_id",          "companies",          "CASCADE",                            "#5 workspace/company"),
    ("workspaces",           "parent_workspace_id", "workspaces",         "SET NULL (parent_workspace_id)",     "#5 parent across tenants"),
    ("workflows",            "company_id",          "companies",          "CASCADE",                            "#3 workflow -> foreign company"),
    ("workflows",            "template_id",         "workflow_templates", "SET NULL (template_id)",             "#3 workflow -> foreign template"),
    ("threads",              "company_id",          "companies",          "CASCADE",                            "#3 thread -> foreign company"),
]


def _new_name(child: str, col: str) -> str:
    return f"fk_{child}_{col}_partner"


def _existing_single_fk(conn, child: str, col: str) -> str | None:
    """Find the single-column FK on (child, col) by reading pg_constraint.

    Looked up rather than assumed: most of these carry PostgreSQL's generated
    `<table>_<col>_fkey` name, but `workspaces.parent_workspace_id` was created
    explicitly as `fk_workspaces_parent`. A hardcoded guess plus DROP ... IF
    EXISTS would have silently left that one in place -- a weaker constraint
    surviving next to the strong one, which is the very thing this migration is
    removing.
    """
    return conn.execute(sa.text("""
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f'
          AND t.relname = :child
          AND cardinality(c.conkey) = 1
          AND a.attname = :col
    """), {"child": child, "col": col}).scalar_one_or_none()


def _preflight(conn) -> None:
    """Refuse to start unless the schema and the data both fit.

    DDL is transactional in PostgreSQL, so a mid-migration failure rolls back
    cleanly -- but it would report only the first problem. This reports all of
    them at once, which matters when the answer is "go clean up these rows".
    """
    insp = sa.inspect(conn)
    present = set(insp.get_table_names())

    needed: dict[str, set[str]] = {}
    for t, _ in PARENT_UNIQUES:
        needed.setdefault(t, set()).update({"id", "partner_id"})
    for child, col, parent, _, _ in COMPOSITE_FKS:
        needed.setdefault(child, set()).update({col, "partner_id"})
        needed.setdefault(parent, set()).update({"id", "partner_id"})

    problems: list[str] = []
    for table, cols in sorted(needed.items()):
        if table not in present:
            problems.append(f"table {table!r} is missing")
            continue
        have = {c["name"] for c in insp.get_columns(table)}
        problems += [f"{table}.{c} is missing" for c in sorted(cols - have)]
        # A nullable partner_id would silently disable the composite FK.
        for c in insp.get_columns(table):
            if c["name"] == "partner_id" and c["nullable"]:
                problems.append(
                    f"{table}.partner_id is NULLABLE -- MATCH SIMPLE would skip "
                    f"the composite FK entirely; make it NOT NULL first")
    if problems:
        raise RuntimeError("0007 preflight (schema):\n  " + "\n  ".join(problems))

    offenders: list[str] = []
    for child, col, parent, _, ref in COMPOSITE_FKS:
        n = conn.execute(sa.text(f"""
            SELECT count(*) FROM {child} c
            JOIN {parent} p ON p.id = c.{col}
            WHERE c.{col} IS NOT NULL
              AND p.partner_id IS DISTINCT FROM c.partner_id
        """)).scalar_one()
        if n:
            offenders.append(f"{child}.{col} -> {parent}: {n} row(s) cross tenants  [{ref}]")
    if offenders:
        raise RuntimeError(
            "0007 preflight (data): rows already reference another tenant. "
            "These are real cross-tenant references; triage them before the "
            "constraints go on:\n  " + "\n  ".join(offenders))


def upgrade() -> None:
    conn = op.get_bind()
    _preflight(conn)

    for table, name in PARENT_UNIQUES:
        op.create_unique_constraint(name, table, ["id", "partner_id"])

    for child, col, parent, on_delete, _ref in COMPOSITE_FKS:
        # Drop the single-column FK this supersedes. Leaving both would mean two
        # constraints answering "does this reference resolve?" at different
        # strengths -- the weaker one adds nothing and invites the reader to
        # believe it is doing the work.
        legacy = _existing_single_fk(conn, child, col)
        if legacy:
            op.execute(f'ALTER TABLE {child} DROP CONSTRAINT "{legacy}"')

        # Raw SQL rather than op.create_foreign_key: the SET NULL column-list
        # form has no Alembic parameter, and being explicit here is worth more
        # than the abstraction.
        #
        # Production note: on a large live table prefer ADD CONSTRAINT ... NOT
        # VALID followed by VALIDATE CONSTRAINT, which takes a weaker lock. The
        # tables here are small and the preflight has already proven the data
        # is clean, so this validates inline.
        op.execute(
            f'ALTER TABLE {child} ADD CONSTRAINT "{_new_name(child, col)}" '
            f'FOREIGN KEY ({col}, partner_id) '
            f'REFERENCES {parent} (id, partner_id) '
            f'ON DELETE {on_delete}'
        )


def downgrade() -> None:
    # Restore the single-column FKs under their original names, including the
    # explicitly-named workspaces parent key.
    legacy_names = {
        ("workspaces", "parent_workspace_id"): "fk_workspaces_parent",
    }
    legacy_ondelete = {
        ("partner_activity_log", "actor_user_id"): "SET NULL",
        ("workspaces", "parent_workspace_id"): "SET NULL",
        ("workflows", "template_id"): "SET NULL",
    }

    for child, col, parent, _on_delete, _ref in reversed(COMPOSITE_FKS):
        op.execute(f'ALTER TABLE {child} DROP CONSTRAINT "{_new_name(child, col)}"')
        name = legacy_names.get((child, col), f"{child}_{col}_fkey")
        od = legacy_ondelete.get((child, col), "CASCADE")
        op.execute(
            f'ALTER TABLE {child} ADD CONSTRAINT "{name}" '
            f'FOREIGN KEY ({col}) REFERENCES {parent} (id) ON DELETE {od}'
        )

    for table, name in reversed(PARENT_UNIQUES):
        op.drop_constraint(name, table, type_="unique")
