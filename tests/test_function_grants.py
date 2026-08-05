"""tests/test_function_grants.py

The function half of what 0020 did for tables. Same two-part split:

  - the static one reads the audit view, which is also what 0021's postflight
    reads, so "what counts as a violation" has one definition
  - the probe creates a function and proves the gate, because a default
    privilege only affects objects created after it was set and therefore
    cannot be observed on anything that already exists

The probe is the only one of the two that can fail for the right reason if the
default privilege is ever dropped. The static one would still pass: the existing
functions keep the ACLs 0021 wrote, and nothing would look wrong until somebody
created the next function.
"""
import pytest
from sqlalchemy import text

PROBE = "_execgate_probe"

# Every confined role that evaluates partner_is_active somewhere: app_runtime in
# login and the invitation path, app_dispatcher through its 0018 policies and
# _claim, app_platform because BYPASSRLS skips policies but not function
# privileges. Losing any one of these breaks queries rather than tests.
CALLERS = ["app_runtime", "app_platform", "app_dispatcher"]


def _sqlstate(exc) -> str | None:
    orig = getattr(exc, "orig", exc)
    return getattr(orig, "sqlstate", None)


def test_public_holds_execute_on_nothing(owner_engine):
    """The predicate lives in the view, not here.

    Rewriting it in the test would be a second answer to the question 0021's
    postflight already answers, and the two would eventually disagree about
    proacl IS NULL -- which is the case that matters and the easy one to omit.
    """
    with owner_engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT function_identity, reason "
            "FROM audit_public_function_execute ORDER BY 1")).all()
    assert rows == [], f"PUBLIC can execute: {rows}"


def test_the_callers_kept_the_execute_they_need(owner_engine):
    """The revoke must not have been the whole story.

    Without this, a 0021 that revoked PUBLIC and granted nobody would satisfy
    the view, satisfy the postflight, and break twelve policies at query time.
    An empty audit view is not the same claim as a working system.
    """
    with owner_engine.connect() as conn:
        for role in CALLERS:
            assert conn.execute(text(
                "SELECT has_function_privilege(:r, 'public.partner_is_active(uuid)', "
                "'EXECUTE')"), {"r": role}).scalar_one() is True, role

        assert conn.execute(text(
            "SELECT has_function_privilege('app_runtime', "
            "'public.set_active_partner_billing_contact(text)', 'EXECUTE')")
        ).scalar_one() is True

        # The dispatcher must NOT be able to write a billing contact. Its reach
        # is three tables through three policies; the billing path is not one of
        # them, and a blanket "grant the callers everything" would have handed
        # it over without anyone noticing.
        assert conn.execute(text(
            "SELECT has_function_privilege('app_dispatcher', "
            "'public.set_active_partner_billing_contact(text)', 'EXECUTE')")
        ).scalar_one() is False
        conn.rollback()


def test_a_new_function_is_born_uncallable(owner_engine, runtime_engine):
    """The gate, which no existing function can demonstrate.

    A default privilege applies only to objects created after it was set, so
    every function in the schema would look identical whether or not the gate
    exists. The only way to observe it is to create one.
    """
    with owner_engine.connect() as oconn:
        oconn.execute(text(
            f"CREATE FUNCTION {PROBE}() RETURNS integer LANGUAGE sql "
            f"IMMUTABLE AS $$ SELECT 1 $$"))
        oconn.commit()
        try:
            with runtime_engine.connect() as rconn:
                assert rconn.execute(text(
                    "SELECT has_function_privilege('app_runtime', "
                    f"'public.{PROBE}()', 'EXECUTE')")).scalar_one() is False

                with pytest.raises(Exception) as exc:
                    rconn.execute(text(f"SELECT public.{PROBE}()"))
                assert _sqlstate(exc.value) == "42501", repr(exc.value)
        finally:
            oconn.execute(text(f"DROP FUNCTION IF EXISTS {PROBE}()"))
            oconn.commit()


def test_probe_function_left_no_residue(owner_engine):
    """A leaked probe would sit in public schema with no grants, which is
    invisible to both audit views -- nothing else would report it."""
    with owner_engine.connect() as conn:
        assert conn.execute(text(
            "SELECT to_regprocedure(:n)"), {"n": f"public.{PROBE}()"}
        ).scalar() is None
