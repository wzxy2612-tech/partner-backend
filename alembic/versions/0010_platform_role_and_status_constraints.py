"""platform-role integrity, and status-field state machines

Two classes of "the database accepts a state no correct caller would write",
both of which RLS cannot stop because the runtime role has same-tenant DML.

#1 (HIGH) -- privilege escalation through a forgeable membership.

    is_platform_admin was tightened last round to require the
    platform_super_admin ROLE rather than the absence of a tenant. But nothing
    stopped app_runtime, inside partner A's own RLS scope, from inserting:

        INSERT INTO memberships (partner_id=A, scope_type='partner',
                                 scope_id=A, role='platform_super_admin')

    On the next login that user resolves as a platform admin. The read-side
    inference was fixed; the write-side integrity of the data it reads was not.
    A grant is only meaningful if the tuple it lives in is well-formed, and that
    is a database fact, not an application convention.

    The constraint makes the platform role and the platform tuple co-require
    each other, in BOTH directions:
      * platform_super_admin  =>  partner_id = NIL AND scope='platform' AND scope_id = NIL
      * scope = 'platform'     =>  role = platform_super_admin
    so neither a partner-scoped platform admin nor a platform-scoped partner
    role can exist. app_runtime is confined to partner A's scope by RLS and
    cannot write partner_id = NIL anyway, but the CHECK is the fail-closed floor
    that does not depend on that argument holding.

#6 (MED) -- status columns were unconstrained VARCHAR.

    invitations.status, connectors.status, workflows.status accepted any string,
    and worse, the correlated invariants were unenforced: a connector could be
    status='verified' with verified_at IS NULL, which verified_kinds() then
    treats as a usable connector. The status and its timestamp are two facts
    about one thing; nothing kept them agreeing.

    CHECKs pin the legal enum values AND the correlations:
      * connector 'verified'   <=> verified_at IS NOT NULL
      * invitation 'accepted'  <=> accepted_at IS NOT NULL
      * invitation 'pending'    =>  accepted_at IS NULL
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

NIL = "00000000-0000-0000-0000-000000000000"


def upgrade() -> None:
    conn = op.get_bind()

    # ---- #1: the platform role and the platform tuple imply each other -----
    # Preflight: surface any existing row that the constraint would reject,
    # naming it rather than failing on an opaque constraint violation.
    bad = conn.execute(sa.text(f"""
        SELECT id, role, partner_id, scope_type, scope_id FROM memberships
        WHERE (role = 'platform_super_admin'
               AND NOT (partner_id = '{NIL}'::uuid
                        AND scope_type = 'platform'
                        AND scope_id = '{NIL}'::uuid))
           OR (scope_type = 'platform' AND role <> 'platform_super_admin')
    """)).all()
    if bad:
        rows = "\n  ".join(
            f"membership {r.id}: role={r.role} partner={r.partner_id} "
            f"scope={r.scope_type}/{r.scope_id}" for r in bad)
        raise RuntimeError(
            "0010 preflight: memberships violate the platform-role tuple. "
            "A platform_super_admin not anchored to the platform tenant is "
            "exactly the escalation this constraint closes -- triage before "
            "applying:\n  " + rows)

    op.create_check_constraint(
        "ck_membership_platform_tuple", "memberships",
        f"(role <> 'platform_super_admin' "
        f"  OR (partner_id = '{NIL}'::uuid "
        f"      AND scope_type = 'platform' "
        f"      AND scope_id = '{NIL}'::uuid)) "
        f"AND (scope_type <> 'platform' OR role = 'platform_super_admin')")

    # ---- #6: status enums + correlated timestamps -------------------------
    for table, col, vals in [
        ("invitations", "status", ("pending", "accepted", "revoked", "expired")),
        ("connectors", "status", ("unverified", "verified")),
        ("workflows", "status", ("draft", "active", "archived")),
    ]:
        bad = conn.execute(sa.text(
            f"SELECT DISTINCT {col} FROM {table} "
            f"WHERE {col} <> ALL(:vals)"), {"vals": list(vals)}).scalars().all()
        if bad:
            raise RuntimeError(
                f"0010 preflight: {table}.{col} has values outside "
                f"{vals}: {bad}. Reconcile before adding the CHECK.")
        allowed = ", ".join(f"'{v}'" for v in vals)
        op.create_check_constraint(
            f"ck_{table}_{col}_enum", table, f"{col} IN ({allowed})")

    # Correlated invariants. Preflight each so a violation is named, not opaque.
    correlations = [
        ("connectors", "ck_connector_verified_at",
         "(status = 'verified') = (verified_at IS NOT NULL)",
         "status='verified' with verified_at IS NULL (or the reverse)"),
        ("invitations", "ck_invitation_accepted_at",
         "(status = 'accepted') = (accepted_at IS NOT NULL)",
         "status='accepted' disagreeing with accepted_at"),
        ("invitations", "ck_invitation_pending_no_accept",
         "(status <> 'pending') OR (accepted_at IS NULL)",
         "status='pending' with a non-null accepted_at"),
    ]
    for table, name, expr, desc in correlations:
        n = conn.execute(sa.text(
            f"SELECT count(*) FROM {table} WHERE NOT ({expr})")).scalar_one()
        if n:
            raise RuntimeError(
                f"0010 preflight: {n} row(s) in {table} violate '{desc}'. "
                f"These are the exact inconsistency the constraint prevents; "
                f"fix the rows first.")
        op.create_check_constraint(name, table, expr)


def downgrade() -> None:
    for table, name in [
        ("invitations", "ck_invitation_pending_no_accept"),
        ("invitations", "ck_invitation_accepted_at"),
        ("connectors", "ck_connector_verified_at"),
        ("workflows", "ck_workflows_status_enum"),
        ("connectors", "ck_connectors_status_enum"),
        ("invitations", "ck_invitations_status_enum"),
        ("memberships", "ck_membership_platform_tuple"),
    ]:
        op.drop_constraint(name, table, type_="check")
