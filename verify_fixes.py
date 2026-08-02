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
    "alembic/versions/0011_rls_active_state_gate.py",
]

# def test_ count per file, after this round's patches. test_bypass_truth_table
# parametrizes into 5. Baseline was 96 functions / 100 collected; this round
# adds two test files (counts filled in once written).
EXPECTED_DEF_TESTS = 96 + 11 + 12 + 6 + 6   # +8 TOCTOU concurrency tests
EXPECTED_COLLECTED = 100 + 11 + 12 + 6 + 6


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
