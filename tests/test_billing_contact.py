"""Billing-contact controls: partner self-service, confined to the calling scope.

The shape of the interesting question changed in 0015. When the service took a
partner_id, "which row gets written" was a caller-supplied fact and the test
worth writing was "you cannot name someone else's". The tenant is now read from
the transaction scope inside a SECURITY DEFINER function, so there is no other
partner to name -- and the question becomes what happens when there is no scope
at all.
"""
from sqlalchemy import text

from app.services.partners import get_billing_contact, set_billing_contact


def test_set_and_get(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        assert set_billing_contact(db, "bill@a.test") == 1
        assert get_billing_contact(db, ids.partner_a) == "bill@a.test"


def test_an_unscoped_session_writes_nothing(runtime_engine):
    """The NULL-tenant branch, which is the one that has to fail closed.

    A tenant expression that evaluated to NULL and fell through to an
    unqualified UPDATE would rewrite every partner in the table. The GUC is set
    to the empty string rather than left alone on purpose: connections come from
    a pool and other tests set this session-wide, so "never set" is not a state
    this test can assume. Empty string is also what 0004 hardened NULLIF against,
    so the two cases are the same case here.
    """
    with runtime_engine.connect() as c:
        c.execute(text("SELECT set_config('app.partner_id', '', false)"))
        ok = c.execute(text(
            "SELECT public.set_active_partner_billing_contact('nobody@x.test')"
        )).scalar_one()
        assert ok is False
        c.rollback()
