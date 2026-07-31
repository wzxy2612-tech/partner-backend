import enum


class BillingSource(str, enum.Enum):
    stripe = "stripe"    # direct customer, billed via the existing Stripe flow
    partner = "partner"  # partner-managed, bypasses Stripe


class PartnerStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"


class Role(str, enum.Enum):
    platform_super_admin = "platform_super_admin"
    partner_super_admin = "partner_super_admin"
    company_admin = "company_admin"
    author = "author"
    read_only = "read_only"


class ScopeType(str, enum.Enum):
    platform = "platform"
    partner = "partner"
    company = "company"
    workspace = "workspace"
