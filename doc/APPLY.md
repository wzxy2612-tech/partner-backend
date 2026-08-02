# Hotfix — 3 test failures (no migration change)

Not 100 passed: it was 3 failed, 97 passed. All three are mistakes I introduced,
none are in your DB or the migrations. Only two test files change; 0007/0008/0009
are untouched, so no re-migration and no image rebuild for schema — but you DO
need `make up` so the container picks up the edited test files (COPY, not mount).

## What the three were

1+2. tests/test_cross_table_isolation.py — I wrote `'x'*64` to build a token
     hash. That is Python. In SQL it means "cast 'x' to integer, multiply by 64"
     and errors out. The INSERT died BEFORE reaching the composite FK, so those
     two tests were never actually exercising the cross-tenant rejection they
     claim to — a false negative wearing a guard's clothes. Fixed to
     repeat('x',64) / repeat('y',64). Traced against the schema: both inserts
     now reach the FK and are rejected as intended (the pair (USER_B,PARTNER_A)
     does not exist in users(id,partner_id)), and they run under platform_ctx
     (BYPASSRLS), so a pass isolates the FK as the thing doing the work.

3.   tests/conftest.py — I seeded the 0009 platform admin as
     billing_source='stripe'. It is not a direct customer.
     test_tenant_isolation.py::test_platform_path_is_unchanged defines the
     direct-customer set as billing_source='stripe' and correctly caught the
     admin leaking in. The test is right; the seed was wrong. Changed to
     'partner' — the only non-Stripe value, and the platform tenant already
     carries partner semantics, so it does not pollute the direct-customer
     invariant. (Same shape as the is_platform bug: a binary field made to carry
     a third case.)

## Apply

    cd ~/workspace/partner-backend
    unzip -o /path/to/fix_tests.zip
    make up                                  # container re-COPYs the two test files
    make test                                # expect 100 passed

verify_fixes.py is unaffected (it checks source, and these were test-only edits),
but re-running it does no harm.
