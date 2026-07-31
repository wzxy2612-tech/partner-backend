"""Truth table for the Stripe-bypass decision -- pure, no DB."""
import pytest

from app.services.billing import should_bypass_stripe
from app.models.enums import BillingSource, PartnerStatus


@pytest.mark.parametrize("billing,status,expected", [
    (BillingSource.partner, PartnerStatus.active, True),     # partner-managed, active -> bypass
    (BillingSource.partner, PartnerStatus.suspended, False), # suspended -> no bypass
    (BillingSource.stripe, PartnerStatus.active, False),     # direct customer -> Stripe
    (BillingSource.stripe, None, False),                     # direct customer, no partner
    (BillingSource.partner, None, False),                    # partner-managed but no partner status
])
def test_bypass_truth_table(billing, status, expected):
    assert should_bypass_stripe(billing, status) is expected
