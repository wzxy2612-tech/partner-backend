"""Stripe-bypass decision as a pure function.

A single authority for one fact: "does this user bypass Stripe?" Partner-managed
users on an active partner bypass the existing Stripe flow; everyone else (direct
customers, and users of a suspended partner) goes through it. Pure -> trivially
unit-testable with a full truth table, no DB.
"""
from app.models.enums import BillingSource, PartnerStatus


def should_bypass_stripe(billing_source: BillingSource,
                         partner_status: PartnerStatus | None) -> bool:
    return billing_source == BillingSource.partner and partner_status == PartnerStatus.active
