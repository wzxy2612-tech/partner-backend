"""Parent-hub branding inheritance: company base <- hub <- workspace override."""
from app.services import branding

# Seed (from conftest): Company A branding {color: navy, logo: co-a};
# Hub A branding {logo: hub-a}; Child A branding {} (parent = Hub A).


def test_resolve_inherits_company_then_hub(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        eff = branding.resolve_branding(db, ids.workspace_a_child)
    assert eff["color"] == "navy"   # inherited from the company
    assert eff["logo"] == "hub-a"   # hub overrides the company's logo


def test_workspace_override_wins(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        branding.set_workspace_branding(db, ids.workspace_a_child, {"logo": "child-a"})
        eff = branding.resolve_branding(db, ids.workspace_a_child)
    assert eff["logo"] == "child-a"  # nearest ancestor (self) wins
    assert eff["color"] == "navy"    # still inherited from the company


def test_company_branding_is_the_base(ids, partner_orm):
    with partner_orm(ids.partner_a) as db:
        branding.set_company_branding(db, ids.company_a, {"color": "red", "font": "serif"})
        eff = branding.resolve_branding(db, ids.workspace_a_child)
    assert eff["color"] == "red" and eff["font"] == "serif"
    assert eff["logo"] == "hub-a"    # hub override still applies over the new base
