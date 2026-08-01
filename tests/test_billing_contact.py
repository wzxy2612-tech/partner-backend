"""Billing-contact controls: partner self-service, confined to the own row."""
from app.services.partners import get_billing_contact, set_billing_contact


def test_set_and_get(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        assert set_billing_contact(db, ids.partner_a, "bill@a.test") == 1
        assert get_billing_contact(db, ids.partner_a) == "bill@a.test"


def test_cannot_set_another_partners_contact(ids, partner_orm):
    # scoped to partner A, attempt to write partner B's row
    with partner_orm(ids.partner_a) as db:
        n = set_billing_contact(db, ids.partner_b, "evil@a.test")
    assert n == 0  # RLS partner_self_isolation -> zero rows touched
