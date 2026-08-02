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
]

REQUIRED_FILES = [
    "alembic/versions/0007_composite_tenant_fks.py",
    "alembic/versions/0008_value_constraints_and_grants.py",
    "alembic/versions/0009_platform_tenant.py",
    "tests/test_cross_table_isolation.py",
    "tests/test_platform_authorization.py",
]

# def test_ count per file, after the patches. test_billing_bypass's single
# function parametrizes into 5, so pytest should collect 100.
EXPECTED_DEF_TESTS = 96
EXPECTED_COLLECTED = 100


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
