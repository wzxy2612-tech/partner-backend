"""materialize the platform tenant, and close the last two unbacked partner_ids

The nil UUID has denoted "the platform tenant" since 0002 -- it is the default
for `users.partner_id` and `sessions.partner_id`, and every RLS policy is
written so that a partner scope can never equal it. What it never had was a row.

That gap had two consequences:

1. `users.partner_id` and `sessions.partner_id` were the only partner_id columns
   in the schema with no foreign key, because there was nothing for the nil
   value to reference. Both could hold a partner id that does not exist.

2. A platform administrator could not be represented at all. `memberships` has
   a hard FK to `partners`, so there was nowhere to put a `platform_super_admin`
   grant -- which is why authorization had to be inferred from the ABSENCE of a
   tenant, and why every direct Stripe customer was a platform operator (0007's
   sibling commit). The sentinel was doing a row's job without being one.

Making it a row is not a new hack layered on the old one; it is the existing
design finally being written down where the database can enforce it. Every
partner_id in the schema is now FK-backed.

ON DELETE RESTRICT, not CASCADE, on both new FKs. The purge job already deletes
a partner's users explicitly before the partner. Under RESTRICT, a future path
that forgets that step fails loudly; under CASCADE it would silently delete user
rows -- and deleting the platform tenant would silently delete every direct
customer. Forgetting should fail closed.

The platform row is additionally protected by a trigger. RESTRICT alone leaves a
window: with zero direct customers the row is deletable, and the next signup
would then fail on a constraint that names nothing recognisable. The trigger
states the structural fact in the one place that cannot be bypassed by a code
path nobody remembered.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

NIL = "00000000-0000-0000-0000-000000000000"

NEW_FKS = [
    # (table, constraint name)
    ("users", "fk_users_partner"),
    ("sessions", "fk_sessions_partner"),
]


def upgrade() -> None:
    conn = op.get_bind()

    # --- 1. the platform tenant, as an actual row -------------------------
    #
    # partners has FORCE ROW LEVEL SECURITY (0002), so its self-isolation policy
    # -- id = current_setting('app.partner_id') -- applies to the migration's
    # owner role too. That FORCE is correct and is left untouched: the whole
    # point of forcing it is that not even the owner may reach across tenants,
    # and relaxing it here to make one INSERT convenient would be exactly the
    # "loosen the adjudicator so the write succeeds" move this schema is built
    # to reject. (The first cut of this migration hit precisely that wall, which
    # is FORCE doing its job.)
    #
    # The row is not an exception to the policy; it satisfies it. Setting the
    # scope to NIL makes the check `id = NIL` true for exactly this row, and NIL
    # is the tenant this row legitimately belongs to. This is the same context
    # the platform path runs under -- the migration reaches it via the GUC
    # because it holds an owner connection rather than the app's BYPASSRLS
    # platform connection, not by carving out a hole.
    #
    # SET LOCAL: scoped to this migration's transaction, discarded on commit.
    op.execute(f"SET LOCAL app.partner_id = '{NIL}'")
    op.execute(f"""
        INSERT INTO partners (id, name, status)
        VALUES ('{NIL}'::uuid, 'Platform', 'active')
        ON CONFLICT (id) DO NOTHING
    """)

    # --- 2. preflight: any partner_id that references nothing? ------------
    # Adding the FKs would otherwise fail with an error that names a constraint
    # rather than the rows causing it.
    orphans: list[str] = []
    for table, _ in NEW_FKS:
        rows = conn.execute(sa.text(f"""
            SELECT t.partner_id, count(*) AS n
            FROM {table} t
            LEFT JOIN partners p ON p.id = t.partner_id
            WHERE p.id IS NULL
            GROUP BY t.partner_id
            ORDER BY n DESC
        """)).all()
        orphans += [f"{table}: {n} row(s) reference partner {pid}, which does not exist"
                    for pid, n in rows]
    if orphans:
        raise RuntimeError(
            "0009 preflight: rows point at a partner with no row. These have "
            "been unconstrained until now, so they may be real orphans from a "
            "deleted partner; decide what they should become rather than "
            "letting the migration guess:\n  " + "\n  ".join(orphans))

    for table, name in NEW_FKS:
        op.execute(
            f'ALTER TABLE {table} ADD CONSTRAINT "{name}" '
            f'FOREIGN KEY (partner_id) REFERENCES partners (id) ON DELETE RESTRICT')

    # --- 3. the platform row is structural ---------------------------------
    op.execute(f"""
        CREATE OR REPLACE FUNCTION protect_platform_tenant() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION
            'the platform tenant ({NIL}) is structural and cannot be deleted';
        END;
        $$ LANGUAGE plpgsql;
    """)
    # WHEN in the trigger definition, so the function body never runs for an
    # ordinary partner -- no per-row overhead on the purge job's deletes.
    op.execute(f"""
        CREATE TRIGGER trg_protect_platform_tenant
        BEFORE DELETE ON partners
        FOR EACH ROW WHEN (OLD.id = '{NIL}'::uuid)
        EXECUTE FUNCTION protect_platform_tenant();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_protect_platform_tenant ON partners")
    op.execute("DROP FUNCTION IF EXISTS protect_platform_tenant()")
    for table, name in reversed(NEW_FKS):
        op.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{name}"')
    # Leave the platform row in place: memberships and any direct-customer rows
    # may reference it, and dropping it is not required to reach 0008's state.
