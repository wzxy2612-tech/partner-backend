"""Cross-table reference ownership.

The ten negative tests in test_tenant_isolation.py all ask the same shape of
question: "under tenant A's scope, can I SEE or WRITE tenant B's row in table
X?" Every one of them passes, and every one of them was blind to a second
question the schema also has to answer:

    "under tenant A's scope, can I write MY OWN row that POINTS AT tenant B's?"

RLS does not answer that, and cannot: PostgreSQL exempts referential-integrity
checks from row security by design, so an FK trigger looks up the parent row
without any tenant scope and happily finds it. Nine single-column FKs meant
nine ways to build a row in A referring to B. An external audit found them; the
existing suite could not have, because it shared the assumption that tenant
safety is a visibility property.

Half of these run on the PLATFORM path on purpose. There RLS contributes
nothing at all (BYPASSRLS), so a passing test isolates the composite FK as the
only thing doing the work -- which is the claim being made.
"""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError


def _fails(conn, sql, **params):
    """Run a statement expected to violate a constraint. Uses a SAVEPOINT so the
    surrounding fixture transaction survives to run the next assertion."""
    sp = conn.begin_nested()
    try:
        conn.execute(text(sql), params)
    except IntegrityError:
        sp.rollback()
        return True
    sp.rollback()
    return False


# --- the FK holds where RLS is absent ---------------------------------------

def test_workflow_cannot_reference_another_tenants_company(ids, platform_ctx):
    """Partner A's workflow pointing at Partner B's company. On the platform
    path, so this is the composite FK alone -- no RLS involved."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO workflows (partner_id, company_id, name) "
            "VALUES (:a, :cb, 'stolen')",
            a=str(ids.partner_a), cb=str(ids.company_b))


def test_thread_cannot_reference_another_tenants_company(ids, platform_ctx):
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO threads (partner_id, company_id, subject) "
            "VALUES (:a, :cb, 'stolen')",
            a=str(ids.partner_a), cb=str(ids.company_b))


def test_workspace_parent_cannot_be_in_another_tenant(ids, platform_ctx):
    """#5's cross-tenant half. Same-company parents inside one partner remain a
    service-layer rule; crossing partners is refused by the schema."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO workspaces (partner_id, company_id, parent_workspace_id, name) "
            "VALUES (:a, :ca, :wb, 'reparented')",
            a=str(ids.partner_a), ca=str(ids.company_a), wb=str(ids.workspace_b))


def test_session_cannot_bind_a_user_from_another_tenant(ids, platform_ctx):
    """#4. A session row claiming partner A while pointing at partner B's user
    is how a token gets authenticated as somebody else's identity."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO sessions (user_id, partner_id, token_hash, expires_at) "
            "VALUES (:ub, :a, repeat('x', 64), now() + interval '1 day')",
            ub=str(ids.user_b), a=str(ids.partner_a))


def test_invitation_cannot_target_another_tenants_user(ids, platform_ctx):
    """#2. Redemption sets a password by user_id, so an invitation owned by A
    but pointing at B's user is a password reset for somebody else's account."""
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO invitations (partner_id, user_id, email, token_hash, expires_at) "
            "VALUES (:a, :ub, 'x@y.test', repeat('y', 64), now() + interval '1 day')",
            a=str(ids.partner_a), ub=str(ids.user_b))


def test_membership_cannot_bind_another_tenants_user(ids, platform_ctx):
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO memberships (user_id, partner_id, scope_type, scope_id, role) "
            "VALUES (:ub, :a, 'company', :ca, 'company_admin')",
            ub=str(ids.user_b), a=str(ids.partner_a), ca=str(ids.company_a))


def test_activity_actor_cannot_be_another_tenants_user(ids, platform_ctx):
    with platform_ctx() as c:
        assert _fails(c,
            "INSERT INTO partner_activity_log (partner_id, actor_user_id, event_type) "
            "VALUES (:a, :ub, 'partner.suspended')",
            a=str(ids.partner_a), ub=str(ids.user_b))


# --- and under RLS, which is how the audit reproduced it --------------------

def test_workflow_cross_reference_also_refused_under_rls(ids, partner_ctx):
    """The audit's reproduction: inside partner A's RLS transaction this INSERT
    used to succeed. RLS never objected -- company B is simply invisible to the
    policy, and the FK trigger that does see it was only checking `id`."""
    with partner_ctx(ids.partner_a) as c:
        assert _fails(c,
            "INSERT INTO workflows (partner_id, company_id, name) "
            "VALUES (:a, :cb, 'stolen')",
            a=str(ids.partner_a), cb=str(ids.company_b))


# --- and the legitimate cases still work ------------------------------------

def test_same_tenant_references_still_succeed(ids, partner_ctx):
    """The constraints must be tight, not merely refusing. A partner writing
    inside its own tenant is unaffected."""
    with partner_ctx(ids.partner_a) as c:
        c.execute(text(
            "INSERT INTO workflows (partner_id, company_id, name) "
            "VALUES (:a, :ca, 'legit')"),
            {"a": str(ids.partner_a), "ca": str(ids.company_a)})
        c.execute(text(
            "INSERT INTO workspaces (partner_id, company_id, parent_workspace_id, name) "
            "VALUES (:a, :ca, :wp, 'legit child')"),
            {"a": str(ids.partner_a), "ca": str(ids.company_a),
             "wp": str(ids.workspace_a_parent)})


def test_null_child_reference_is_still_allowed(ids, platform_ctx):
    """MATCH SIMPLE: a NULL child column means "no reference", so the composite
    FK is not checked. Root workspaces and template-less workflows depend on
    this staying true."""
    with platform_ctx() as c:
        sp = c.begin_nested()
        c.execute(text(
            "INSERT INTO workflows (partner_id, company_id, template_id, name) "
            "VALUES (:a, :ca, NULL, 'no template')"),
            {"a": str(ids.partner_a), "ca": str(ids.company_a)})
        sp.rollback()
