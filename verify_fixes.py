#!/usr/bin/env python3
"""Check that the fixes are actually present in the code that is running.

Written because a green test run did not mean what it looked like. 87 tests
passed while the central security fix was not deployed at all: the migrations
had landed, the modified source files had not, and every test that would have
noticed was itself one of the files that did not land. The suite was measuring
a tree that no longer matched the one it was shipped with.

So this deliberately does not count tests, and does not import the application.
It reads the source files and looks for the specific edit -- a different signal
from the one the test suite uses, chosen so the two cannot fail together.

Usage, from the repo root or inside the container:

    python3 verify_fixes.py
    docker compose exec api python3 verify_fixes.py
"""
import re
import sys
from pathlib import Path

# (label, path, must_contain, must_NOT_contain)
#
# The negative half matters as much as the positive: several fixes REMOVE a
# bypass, and a file can contain the new code while still carrying the old.
CHECKS = [
    ("#1  require_platform is role-gated",
     "app/deps.py", [r"principal\.is_platform_admin"], [r"principal\.is_platform\s+or"]),

    ("#1  routing flag renamed everywhere",
     "app/deps.py", [r"is_platform_path"], [r"principal\.is_platform\b(?!_)"]),

    ("#1  Principal exposes both facts separately",
     "app/auth/principal.py", [r"is_platform_path", r"def is_platform_admin"], []),

    ("#1  principal_can bypass parameter removed",
     "app/services/rbac.py", [], [r"is_platform"]),

    ("#4  authenticate rejects session/user tenant mismatch",
     "app/auth/principal.py", [r"row\.partner_id != user\.partner_id"], []),

    ("#5  parent workspace validated on create",
     "app/services/workspaces.py", [r"parent workspace belongs to another"], []),

    ("#5  parent walks capped (scopes)",
     "app/services/scopes.py", [r"MAX_SCOPE_DEPTH"], []),

    ("#5  parent walks capped (branding)",
     "app/services/workspaces.py", [r"MAX_SCOPE_DEPTH"], []),

    ("#6  invitation redemption is one atomic claim",
     "app/services/onboarding.py", [r"RETURNING user_id"], [r"if inv is None or inv\.status"]),

    ("#7  connector re-registration resets verification",
     "app/services/connectors.py",
     [r"status = 'unverified', verified_at = NULL", r"RETURNING id, status"], []),

    ("#7  router reports the persisted status",
     "app/routers/workflows.py", [r'"status": cstatus'], [r'"status": "unverified"']),

    ("#8  workspace listing filtered by grants",
     "app/routers/workspaces.py", [r"principal_can\("], []),

    ("#9  CSV onboarding persists name",
     "app/services/onboarding.py", [r"INSERT INTO users \(id, email, name,"], []),

    ("#11 retention window has a floor",
     "app/routers/maintenance.py", [r"ge=1"], []),

    ("#12 domain compared exactly, not as a LIKE pattern",
     "app/services/partners.py", [r"split_part"], []),

    ("#13 malformed cursor is a client error",
     "app/services/activity.py", [r"class InvalidCursor"], []),

    ("#13 router translates it to 422",
     "app/routers/activity.py", [r"InvalidCursor"], []),

    ("#13 hidden template is 404, not 500",
     "app/routers/workflows.py", [r"template not found"], []),

    ("#14 usage rejects negative tokens / bad periods",
     "app/services/token_usage.py", [r"PERIOD_RE"], []),

    ("0009 platform tenant guarded in lifecycle",
     "app/services/partners.py", [r"platform tenant cannot be suspended"], []),

    ("0009 conftest preserves the platform tenant",
     "tests/conftest.py", [r"DELETE FROM partners WHERE id <> :nil"], []),

    ("0009 conftest seeds a real platform admin",
     "tests/conftest.py", [r"platform_super_admin"], []),

    # ---- round 2: #1 #6 #8 #9 #10 #12 -----------------------------------
    ("R2 #1  is_platform_admin checks the full platform tuple",
     "app/auth/principal.py",
     [r"scope_type == ScopeType\.platform", r"self\.partner_id == NIL"],
     [r"return Role\.platform_super_admin in self\.roles"]),

    ("R2 #1  membership platform-tuple CHECK exists",
     "alembic/versions/0010_platform_role_and_status_constraints.py",
     [r"ck_membership_platform_tuple"], []),

    ("R2 #6  status enum + correlation CHECKs exist",
     "alembic/versions/0010_platform_role_and_status_constraints.py",
     [r"ck_connector_verified_at", r"ck_invitation_accepted_at",
      r"ck_connectors_status_enum"], []),

    ("R2 #8  cursor validates the UUID tail",
     "app/services/activity.py", [r"cid = UUID\(id_s\)"], []),

    ("R2 #9  invitation password has a length floor",
     "app/routers/invitations.py", [r"min_length=12"], [r"^\s*password: str\s*$"]),

    ("R2 #10 session model declares the composite FK",
     "app/models/session.py",
     [r"ForeignKeyConstraint", r'\["user_id", "partner_id"\]'],
     [r'ForeignKey\("users\.id"']),

    ("R2 #10 workflow model declares composite FKs, not single-col",
     "app/models/connector.py",
     [r"fk_workflows_company_id_partner"],
     [r'ForeignKey\("companies\.id"']),

    ("R2 #10 token_usage checks mirrored (self-caught drift)",
     "app/models/usage.py",
     [r"ck_token_usage_tokens_nonneg", r"ck_token_usage_period_format"], []),

    ("R2 #12 create_workspace rejects over-deep chains",
     "app/services/workspaces.py",
     [r"WorkspaceTooDeep", r"depth > MAX_SCOPE_DEPTH"], []),

    ("R2 #12 routers map ScopeChainTooDeep to 4xx",
     "app/routers/workspaces.py", [r"ScopeChainTooDeep", r"HTTP_409_CONFLICT"], []),

    ("R2 #12 branding router maps ScopeChainTooDeep to 4xx",
     "app/routers/branding.py", [r"ScopeChainTooDeep"], []),

    # ---- round 2b: alembic check convergence ----------------------------
    ("R2b #10 SET NULL FKs carry their column list",
     "app/models/activity_log.py", [r"SET NULL \(actor_user_id\)"], []),

    ("R2b #10 workflows/workspaces SET NULL column lists",
     "app/models/connector.py", [r"SET NULL \(template_id\)"], []),

    ("R2b #10 workspace parent SET NULL column list",
     "app/models/workspace.py", [r"SET NULL \(parent_workspace_id\)"], []),

    ("R2b #10 subscriptions is modelled (autogen wanted to DROP it)",
     "app/models/subscription.py", [r'__tablename__ = "subscriptions"'], []),

    ("R2b #10 subscriptions registered in metadata",
     "app/models/__init__.py", [r"from app\.models\.subscription import Subscription"], []),

    ("R2b #10 indexes declared (autogen wanted to drop 17)",
     "app/models/activity_log.py", [r"ix_activity_partner_created"], []),

    # ---- round 3: TOCTOU (#2 #3 #4) -------------------------------------
    ("R3 #2  RLS gates on partner active-state",
     "alembic/versions/0011_rls_active_state_gate.py",
     [r"partner_is_active", r"partner_id = \{GUC\} AND partner_is_active"], []),

    ("R3 #2  active-state predicate has ONE shared definition",
     "alembic/versions/0011_rls_active_state_gate.py",
     [r"GRANT EXECUTE ON FUNCTION partner_is_active", r"PARTNER_ID_TABLES"], []),

    ("R3 #3  login refuses a suspended partner",
     "app/routers/auth.py", [r"FOR SHARE", r"partner is suspended"], []),

    ("R3 #4  lifecycle transitions lock the partner row",
     "app/services/partners.py", [r"def _lock_partner", r"FOR UPDATE"], []),

    ("R3 #4  purge locks candidates and deletes conditionally",
     "app/services/maintenance.py",
     [r"FOR UPDATE SKIP LOCKED", r"RETURNING id"], []),

    ("R3b  partners policy stays ungated (no policy->function->policy loop)",
     "alembic/versions/0011_rls_active_state_gate.py",
     [r"REVOKE INSERT, UPDATE, DELETE ON partners FROM app_runtime"],
     [r"partner_self_isolation ON partners \"\)\n    op\.execute\(\s*\n?\s*f\"CREATE POLICY partner_self_isolation.*partner_is_active"]),

    # The CREATE FUNCTION body sits inside a triple-quoted SQL block that
    # _strip_comments removes, so SECURITY INVOKER/DEFINER cannot be asserted
    # here. What IS assertable, and is what actually breaks the recursion:
    # partners must not appear in the gated table list.
    # ---- round 6: outbox ------------------------------------------------
    ("R6 provision cannot send mail at all",
     "app/services/onboarding.py",
     [r"outbox\.enqueue_invitation"], [r"sender\.send_invitation"]),

    ("R6 token is encrypted, never stored plaintext",
     "app/services/outbox.py", [r"encrypt_token\(token, aad\)"], []),

    ("R6 AAD binds ciphertext to its own row",
     "app/services/outbox_crypto.py",
     [r"def build_aad", r"event_id", r"invitation_id", r"partner_id"], []),

    # Was [r"FOR UPDATE SKIP LOCKED"]. R11 joins invitations into the claim, and
    # a bare FOR UPDATE would then lock rows in every joined table -- so the
    # correct form gained an OF clause and this check had to follow it. Kept as
    # a negative too: dropping back to the bare form is silent and would make
    # the dispatcher hold invitations rows across an SMTP call.
    ("R6 dispatcher claims with SKIP LOCKED, locking only the event",
     "app/services/outbox.py",
     [r"FOR UPDATE OF o SKIP LOCKED"],
     [r"[^F] FOR UPDATE SKIP LOCKED"]),

    ("R6 delivery clears the secret in the same statement",
     "app/services/outbox.py",
     [r"status = 'sent', sent_at = now\(\)",
      r"token_ciphertext = NULL, token_nonce = NULL"], []),

    ("R6 dead-letter is terminal and clears the secret",
     "app/services/outbox.py",
     [r"def _dead_letter", r"status = 'failed'"], []),

    # ---- round 5: #11 workspace company boundary ------------------------
    ("R5 #11 parent FK includes company (3 columns)",
     "alembic/versions/0012_workspace_parent_same_company.py",
     [r"parent_workspace_id, partner_id, company_id"], []),

    ("R5 #11 migration refuses on existing cross-company links",
     "alembic/versions/0012_workspace_parent_same_company.py",
     [r"raise RuntimeError", r"offenders = conn\.execute"], []),

    ("R5 #11 scope chain pins company to the target",
     "app/services/scopes.py",
     [r"target_company_id", r"chain\.append\(\(ScopeType\.company, target_company_id\)\)"],
     [r"company_id, partner_id = row\.company_id, row\.partner_id"]),

    ("R5 #11 branding pins company to the target",
     "app/services/workspaces.py",
     [r'\{"id": str\(target_company_id\)\}'], []),

    ("R5 #11 CrossCompanyParent maps to 4xx, not 500",
     "app/routers/branding.py",
     [r"CrossCompanyParent", r"HTTP_409_CONFLICT"], []),

    ("R5 #11 ORM declares the 3-column parent FK",
     "app/models/workspace.py",
     [r"fk_workspaces_parent_partner_company"],
     [r"fk_workspaces_parent_workspace_id_partner"]),

    # ---- round 4: #7 global email uniqueness ----------------------------
    ("R4 #7  cross-tenant precheck runs on the platform path",
     "app/routers/onboarding.py",
     [r"def _resolve_taken", r"platform_session\(\)"], []),

    ("R4 #7  precheck is resolved outside the partner transaction",
     "app/routers/onboarding.py",
     [r"taken = _resolve_taken\(.*\)\n    with session_for_principal"], []),

    ("R4 #7  row error does not disclose ownership",
     "app/services/onboarding.py",
     [r'"email already registered"'], [r"already exists for this partner"]),

    ("R4 #7  conflict matched by constraint name, not message text",
     "app/services/onboarding.py",
     [r"EMAIL_UNIQUE_CONSTRAINT", r"constraint_name"], []),

    ("R4 #7  only the email constraint is reinterpreted",
     "app/services/onboarding.py",
     [r"if _is_email_conflict\(exc\)",
      r"raise EmailAlreadyRegistered\(r\.email\) from exc\s+raise\s"], []),

    ("R4 #7  no test still asserts the ownership-disclosing wording",
     "tests/test_onboarding.py",
     [r"already registered"], [r"already exists"]),

    ("R4 #7  commit maps the conflict to 409",
     "app/routers/onboarding.py",
     [r"HTTP_409_CONFLICT", r"EmailAlreadyRegistered"], []),

    ("R3c  lifecycle revoke is column-scoped, not table-wide",
     "alembic/versions/0011_rls_active_state_gate.py",
     [r"GRANT UPDATE \(billing_contact_email\) ON partners TO app_runtime"], []),

    ("R3b  partners is NOT in the gated policy list (breaks the loop)",
     "alembic/versions/0011_rls_active_state_gate.py",
     [r'PARTNER_ID_TABLES = \['],
     [r'"partners",']),

    # ---- round 7: grant-driven RLS coverage -----------------------------
    # The SQL in this file lives in triple-quoted blocks, which _strip_comments
    # removes -- so has_any_column_privilege / pg_class cannot be asserted here.
    # What IS assertable is the shape that makes the guard independent: it owns
    # a column-grant scan, and it does not borrow any inventory from the code it
    # audits.
    ("R7 coverage guard does not borrow the migration's table list",
     "tests/test_rls_coverage.py",
     [r"COLUMN_GRANT_SQL", r"def reachable", r"def writable"],
     [r"PARTNER_ID_TABLES"]),

    # Roles are enumerated from pg_roles, not listed here. A hardcoded role list
    # is the same disease one level up: app_dispatcher would exist, hold grants,
    # and be invisible until someone remembered to add it.
    ("R10 the guard enumerates roles from the catalog",
     "tests/test_rls_coverage.py",
     [r"ROLE_SQL", r"def confined_roles", r"def bypass_roles",
      r"BYPASS_ROLES = \{"],
     [r"^ROLES = \["]),

    # A BYPASSRLS role does not fail the RLS assertions, it makes them vacuous.
    ("R10 the set of RLS-bypassing roles is pinned in both directions",
     "tests/test_rls_coverage.py",
     [r"actual - declared", r"declared - actual", r"rolsuper"], []),

    ("R10 permissive-true policies are registered and never reach PUBLIC",
     "tests/test_rls_coverage.py",
     [r"PERMISSIVE_TRUE", r'"public" in p\.roles',
      r"set\(PERMISSIVE_TRUE\) - seen"], []),

    ("R7 coverage guard pins its exemptions in BOTH directions",
     "tests/test_rls_coverage.py",
     [r"NOT_FORCED - actually_unforced", r"actually_unforced - NOT_FORCED",
      r"PARTNERS_RUNTIME_COLUMNS"], []),

    ("R7 coverage guard is anchored against a vacuous pass",
     "tests/test_rls_coverage.py",
     [r"anchors = \{", r"assert scan\.policies"], []),

    # ---- round 8: 0014, outbox row security -----------------------------
    ("R8 #1 0014 both enables and forces row security on outbox_events",
     "alembic/versions/0014_outbox_rls_and_bookkeeping.py",
     [r"ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY",
      r"ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY"], []),

    ("R8 #1 the policy is gated and keeps 0004's empty-GUC hardening",
     "alembic/versions/0014_outbox_rls_and_bookkeeping.py",
     [r"NULLIF\(current_setting\('app\.partner_id', true\), ''\)::uuid",
      r"partner_is_active\(\{GUC\}\)",
      r"USING \(\{PREDICATE\}\) WITH CHECK \(\{PREDICATE\}\)"], []),

    ("R8 alembic_version is revoked from the runtime role",
     "alembic/versions/0014_outbox_rls_and_bookkeeping.py",
     [r'BOOKKEEPING = "alembic_version"',
      r"REVOKE ALL ON \{BOOKKEEPING\} FROM app_runtime"], []),

    # A blocked UPDATE under RLS raises nothing -- it affects zero rows. A test
    # that only asserts rowcount proves the write was refused but not that the
    # victim's value survived, and one that only re-reads proves the opposite.
    # Was [r"result\.rowcount == 0"]. Under 0014 a blocked UPDATE affected zero
    # rows; under 0019 the runtime role has no UPDATE at all and it raises. The
    # surviving-value read stays either way -- an exception says the statement
    # was refused, only the read says nothing else got there first.
    ("R8 the redirect test asserts the refusal AND the surviving value",
     "tests/test_outbox_isolation.py",
     [r"_recipient_now\(platform_engine", r"scalar_one\(\) == 1",
      r'_sqlstate\(exc\) == "42501"'],
     [r"result\.rowcount == 0"]),
    # ---- round 9: 0015, the gate gets a second consumer -----------------
    # The function body lives in a triple-quoted block that _strip_comments
    # removes, so SECURITY DEFINER / GET DIAGNOSTICS cannot be asserted here.
    # The signature in FN survives, and it is the thing that matters: a
    # partner_id parameter would make the function silently return false for
    # every tenant instead of raising (see 0015's docstring).
    ("R9 #8 the billing function takes only an email, never a tenant id",
     "alembic/versions/0015_billing_gate_function.py",
     [r"set_active_partner_billing_contact\(text\)"],
     [r"set_active_partner_billing_contact\(uuid"]),

    ("R9 #8 the column grant is revoked and PUBLIC never gets EXECUTE",
     "alembic/versions/0015_billing_gate_function.py",
     [r"REVOKE UPDATE \(billing_contact_email\) ON public\.partners FROM app_runtime",
      r"REVOKE ALL ON FUNCTION \{FN\} FROM PUBLIC",
      r"GRANT EXECUTE ON FUNCTION \{FN\} TO app_runtime"], []),

    ("R9 #8 the service no longer writes partners directly",
     "app/services/partners.py",
     [r"set_active_partner_billing_contact\(CAST\(:e AS text\)\)"],
     [r"UPDATE partners SET billing_contact_email"]),

    # The first cut kept a partner_id parameter the function ignores: called
    # while scoped to A with B's id, it wrote A's row and reported success.
    ("R9 #8 the billing wrapper takes no tenant it would then ignore",
     "app/services/partners.py",
     [r"def set_billing_contact\(db: OrmSession, email: str \| None\)"],
     [r"def set_billing_contact\(db: OrmSession, partner_id"]),

    ("R9 #8 a refused billing write becomes 403, not a reported success",
     "app/routers/partners.py",
     [r"if not set_billing_contact\(", r"HTTP_403_FORBIDDEN"], []),

    # No FOR SHARE here. It required UPDATE privilege on partners, which
    # app_runtime held only through the column grant 0015 revokes -- and it was
    # redundant anyway: suspension revokes the invitation, so the deciding
    # predicate is a column on the row the UPDATE already locks.
    ("R9 #9 redemption is gated, and claims on the invitation's own status",
     "app/services/onboarding.py",
     [r"public\.partner_is_active\(partner_id\)",
      r"status = 'pending' AND expires_at > now\(\)"],
     [r"FROM partners WHERE id = :p FOR SHARE"]),

    # `AND is_active = true` is the exact filter that let a pending invitee
    # survive a domain deactivation: inactive is the normal state for an
    # invited user, so that clause skipped the accounts still at risk.
    ("R9 #9 domain deactivation scans every user on the domain",
     "app/services/partners.py",
     [r"cannot be domain-deactivated", r"_revoke_pending_invitations\(db, partner_id, user_ids="],
     [r"AND is_active = true"]),

    ("R9 #9 revocation clears the queued secret, not just the invitation",
     "app/services/partners.py",
     [r"token_ciphertext = NULL, token_nonce = NULL",
      r"if user_ids is not None", r"if not user_ids"], []),

    # An empty user_ids list means "matched nobody" and must not be read as
    # "no narrowing", which would revoke the whole partner's invitations.
    # A threaded "race" test that never actually blocks is the sequential test
    # wearing a disguise, and it passes just as green. The wait assertion is
    # what makes the overlap a fact rather than a hope.
    ("R9 the redemption races assert the transactions actually overlapped",
     "tests/test_toctou_lifecycle.py",
     [r"def _wait_until_blocked", r"wait_event_type = 'Lock'",
      r"assert _wait_until_blocked\(engine\)",
      r"threading\.Thread"], []),

    # ---- round 11: the claim asks whether the mail is still worth sending -
    ("R11 #5 the claim joins invitations and gates on the shared predicate",
     "app/services/outbox.py",
     [r"i\.id = o\.invitation_id AND i\.partner_id = o\.partner_id",
      r"public\.partner_is_active\(o\.partner_id\)"],
     [r"p\.status = 'active'"]),

    ("R11 #5 dead invitations reach a terminal state with no secret left",
     "app/services/outbox.py",
     [r"def _reap_undeliverable",
      r"token_ciphertext = NULL, token_nonce = NULL ",
      r"result\.terminated\.extend"], []),

    # Suspension is reversible; clearing ciphertext is not. Both halves of that
    # call are pinned -- held now, and deliverable again afterwards -- because
    # holding is only the right answer if the mail actually goes out later.
    ("R11 #5 a suspended partner's event is held, not destroyed",
     "tests/test_outbox_claim.py",
     [r"def test_a_suspended_partners_event_is_held_not_terminated",
      r"def test_reactivation_makes_a_held_event_deliverable_again",
      r'== "55P03"'], []),

    ("R11 alembic_version is revoked from the platform role too",
     "alembic/versions/0016_ledger_revoke_platform.py",
     [r'ROLE = "app_platform"', r"REVOKE ALL ON \{BOOKKEEPING\} FROM \{ROLE\}"], []),

    # ---- round 12: key configuration and rotation -----------------------
    # The constant is gone. A grep for it is the cheapest way to catch it being
    # reintroduced as "just a default".
    ("R12 #3 there is no fallback key and no APP_ENV escape hatch",
     "app/services/outbox_crypto.py",
     [r"KEYS_ENV = \"OUTBOX_KEYS\"", r"def validate_outbox_config"],
     [r"CURRENT_KEY_VERSION = 1", r'b"\\x00" \* KEY_BYTES', r"APP_ENV"]),

    # Two reads of one fact: encrypt used the constant, enqueue wrote it again.
    # The version now travels back with the ciphertext it belongs to.
    ("R12 #6 encryption reports the version, enqueue records what it reported",
     "app/services/outbox_crypto.py",
     [r"def current_key_version", r"return ct, nonce, version"], []),

    ("R12 #6 the row records the version encryption actually used",
     "app/services/outbox.py",
     [r"ciphertext, nonce, key_version = encrypt_token\(token, aad\)",
      r'"kv": key_version'],
     [r"CURRENT_KEY_VERSION"]),

    ("R12 #3 the deployment must supply a key and .env.example must not",
     "docker-compose.yml",
     [r"OUTBOX_KEYS:\?"], []),

    ("R12 startup resolves the key configuration before serving",
     "app/main.py",
     [r"validate_outbox_config\(\)", r"lifespan"], []),

    # ---- round 13: 0017, the state machine as constraints ---------------
    # The old check said nothing about `failed` and never mentioned the nonce.
    # Three named constraints, because this codebase reads diag.constraint_name
    # rather than parsing message text.
    ("R13 #7 every terminal state is constrained, and the old check is gone",
     "alembic/versions/0017_outbox_terminal_invariants.py",
     [r"ck_outbox_pending_has_payload", r"ck_outbox_sent_is_clean",
      r"ck_outbox_failed_is_clean", r"DROP CONSTRAINT IF EXISTS \{OLD_CHECK\}"],
     []),

    # A per-partner GUC loop cannot reach a suspended partner's rows -- the
    # policy gates on partner_is_active too -- so the backfill lifts FORCE for
    # the length of the transaction and asserts it back on.
    ("R13 #7 the backfill can actually see the rows, and restores FORCE",
     "alembic/versions/0017_outbox_terminal_invariants.py",
     # relforcerowsecurity lives in a triple-quoted SQL block that
     # _strip_comments removes; the Python that reads it does not.
     [r"NO FORCE ROW LEVEL SECURITY", r"FORCE ROW LEVEL SECURITY",
      r"if not state\.forced", r"REFUSALS"], []),

    ("R13 #7 the invariants are pinned by constraint name, not message text",
     "tests/test_outbox_invariants.py",
     [r'_constraint\(exc\) == "ck_outbox_failed_is_clean"',
      r'_constraint\(exc\) == "ck_outbox_pending_has_payload"',
      r"def test_every_real_transition_produces_a_legal_row"], []),

    # ---- round 14: the dispatcher exists and is confined ----------------
    # A role provisioned with BYPASSRLS would not fail 0018's policies -- it
    # would make them decoration. The migration refuses rather than proceeding.
    ("R14 #2 0018 refuses a dispatcher that bypasses row security",
     "alembic/versions/0018_dispatcher_role.py",
     [r"rolsuper or role\.rolbypassrls", r"scripts/provision_dispatcher_role\.sql"],
     []),

    # USING (true) decides which rows; the column grant decides which facts.
    ("R14 #2 the dispatcher may record outcomes, not redirect or reassign",
     "alembic/versions/0018_dispatcher_role.py",
     [r"WRITABLE = \[", r"can_move_tenant", r"can_redirect",
      r"can_read_token_hash"],
     [r'"partner_id", "recipient"']),

    ("R14 #2 there is a runnable dispatcher with its own credentials",
     "app/dispatcher.py",
     [r"DISPATCHER_DATABASE_URL", r"dispatch_pending", r"validate_outbox_config"],
     [r"from app\.db import"]),

    # Every refusal in that file is worthless without the matching reach.
    ("R14 #2 the dispatcher tests pair each refusal with a capability",
     "tests/test_dispatcher_role.py",
     [r"def test_the_dispatcher_sees_events_from_every_tenant",
      r"def test_the_dispatcher_can_deliver_end_to_end",
      r"def test_the_dispatcher_does_not_bypass_row_security",
      r"def test_the_dispatcher_cannot_redirect_an_event"], []),

    ("R14 the per-table bypasses are registered with reasons",
     "tests/test_rls_coverage.py",
     [r'\("app_dispatcher", "outbox_events"\)',
      r'\("app_dispatcher", "invitations"\)',
      r'\("app_dispatcher", "partners"\)'], []),

    # ---- round 15: the runtime path becomes append-only -----------------
    # "we granted a list" and "nothing outside the list is reachable" are
    # different claims; only the second one matters, so FORBIDDEN is checked
    # column by column rather than inferred from the grant.
    ("R15 the runtime role may only queue, never read or amend",
     "alembic/versions/0019_runtime_outbox_insert_only.py",
     [r"REVOKE ALL ON outbox_events FROM \{ROLE\}", r"FORBIDDEN = \[",
      r"can_read", r"can_update", r"can_delete"], []),
    # No MUST_NOT here on purpose. A migration contains the inverse of its own
    # change, in downgrade() -- so "this file must not mention GRANT SELECT" is
    # structurally wrong for a migration, and the first version of this check
    # forbade a correct downgrade. The runtime assertion in the postflight is
    # the guard; a text check cannot tell which function a line is in.

    # status and available_at carry server defaults and are not granted, so a
    # tenant has no column through which to express a non-pending event.
    ("R15 enqueue stops naming the columns it is no longer granted",
     "app/services/outbox.py",
     [r"token_ciphertext, token_nonce, key_version\) "],
     [r"key_version, status, available_at", r"'pending', now\(\)\)"]),

    # permission-denied and RLS-violation share SQLSTATE 42501, so the forge
    # test proves the grant exists before attributing the refusal to the policy.
    ("R15 the forge test separates the grant from the policy",
     "tests/test_outbox_isolation.py",
     [r"own_invitation_id", r"insert = text\(",
      r'"p": str\(ids\.partner_a\)'], []),

    ("R9 login consumes the shared predicate instead of its own copy",
     "app/routers/auth.py",
     [r"public\.partner_is_active\(id\)", r"FOR SHARE"],
     [r'row\.status != "active"']),
]

REQUIRED_FILES = [
    "alembic/versions/0007_composite_tenant_fks.py",
    "alembic/versions/0008_value_constraints_and_grants.py",
    "alembic/versions/0009_platform_tenant.py",
    "alembic/versions/0010_platform_role_and_status_constraints.py",
    "tests/test_cross_table_isolation.py",
    "tests/test_platform_authorization.py",
    "tests/test_platform_role_integrity.py",
    "tests/test_workspace_depth.py",
    "tests/test_toctou_lifecycle.py",
    "tests/test_email_uniqueness.py",
    "tests/test_workspace_company_boundary.py",
    "alembic/versions/0012_workspace_parent_same_company.py",
    "scripts/scan_cross_company_parents.sql",
    "alembic/versions/0013_outbox_events.py",
    "app/services/outbox.py",
    "app/services/outbox_crypto.py",
    "app/models/outbox_event.py",
    "tests/test_outbox.py",
    "alembic/versions/0011_rls_active_state_gate.py",
    "tests/test_rls_coverage.py",
    "alembic/versions/0014_outbox_rls_and_bookkeeping.py",
    "tests/test_outbox_isolation.py",
    "alembic/versions/0015_billing_gate_function.py",
    "tests/test_lifecycle_gate.py",
    "alembic/versions/0016_ledger_revoke_platform.py",
    "tests/test_outbox_claim.py",
    "tests/test_outbox_keys.py",
    "alembic/versions/0017_outbox_terminal_invariants.py",
    "tests/test_outbox_invariants.py",
    "scripts/scan_outbox_invariants.sql",
    "alembic/versions/0018_dispatcher_role.py",
    "app/dispatcher.py",
    "scripts/provision_dispatcher_role.sql",
    "tests/test_dispatcher_role.py",
    "alembic/versions/0019_runtime_outbox_insert_only.py",
]

# def test_ count per file, after this round's patches. test_bypass_truth_table
# parametrizes into 5. Baseline was 96 functions / 100 collected; this round
# adds two test files (counts filled in once written).
EXPECTED_DEF_TESTS = 96 + 11 + 12 + 6 + 6 + 9 + 11 + 4 + 12 + 2 + 7 + 10 + 6 + 9   # +9 dispatcher role
EXPECTED_COLLECTED = 100 + 11 + 12 + 6 + 6 + 9 + 11 + 4 + 12 + 2 + 7 + 10 + 6 + 9


def _strip_comments(src: str) -> str:
    """Drop comment lines and docstrings so prose about a fix is not mistaken
    for the fix. The first version of this check matched the word LIKE inside a
    comment explaining why LIKE had been removed."""
    src = re.sub(r'"""(?:.|\n)*?"""', "", src)
    src = re.sub(r"^\s*#.*$", "", src, flags=re.M)
    return src


def main() -> int:
    root = Path(__file__).resolve().parent
    failures: list[str] = []

    print("files that must exist")
    for rel in REQUIRED_FILES:
        ok = (root / rel).is_file()
        print(f"  {'OK  ' if ok else 'MISS'}  {rel}")
        if not ok:
            failures.append(f"missing file: {rel}")

    print("\ncode fixes")
    for label, rel, must, must_not in CHECKS:
        path = root / rel
        if not path.is_file():
            print(f"  MISS  {label}  ({rel} not found)")
            failures.append(label)
            continue
        code = _strip_comments(path.read_text())
        missing = [p for p in must if not re.search(p, code)]
        lingering = [p for p in must_not if re.search(p, code)]
        if missing or lingering:
            why = []
            if missing:
                why.append(f"not found: {missing}")
            if lingering:
                why.append(f"old code still present: {lingering}")
            print(f"  FAIL  {label}  -- {'; '.join(why)}")
            failures.append(label)
        else:
            print(f"  OK    {label}")

    tests_dir = root / "tests"
    if tests_dir.is_dir():
        n = sum(len(re.findall(r"^def test_", f.read_text(), re.M))
                for f in tests_dir.glob("test_*.py"))
        print(f"\ntest functions: {n} (expected {EXPECTED_DEF_TESTS})")
        print(f"pytest should collect {EXPECTED_COLLECTED} "
              f"(test_bypass_truth_table parametrizes 1 -> 5)")
        if n != EXPECTED_DEF_TESTS:
            failures.append(f"test function count {n} != {EXPECTED_DEF_TESTS}")

    print()
    if failures:
        print(f"INCOMPLETE -- {len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        print("\nThe running code does not match the patch set. Do not read a "
              "green test run as confirmation until this is clean.")
        return 1
    print("All checks passed. Now confirm the database side:")
    print(f"  make migrate && make test    -> expect {EXPECTED_COLLECTED} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
