"""Workflow cloning gated by connector verification, and template isolation."""
import uuid

import pytest
from sqlalchemy import text

from app.services import connectors, workflows


def test_missing_connectors_pure():
    assert workflows.missing_connectors(["a", "b", "c"], {"a", "c"}) == ["b"]
    assert workflows.missing_connectors([], {"x"}) == []
    assert workflows.missing_connectors(["a"], set()) == ["a"]


def test_clone_refused_until_connectors_verified(ids, partner_orm):
    tid = uuid.uuid4()
    with partner_orm(ids.partner_a) as db:
        db.execute(text(
            "INSERT INTO workflow_templates (id, partner_id, name, definition, required_connectors) "
            "VALUES (:id, :p, 'Onboarding', '{\"steps\":[1,2]}'::jsonb, '[\"slack\",\"gmail\"]'::jsonb)"),
            {"id": str(tid), "p": str(ids.partner_a)})
        connectors.register_connector(db, ids.partner_a, "slack")
        connectors.register_connector(db, ids.partner_a, "gmail")
        connectors.verify_connector(db, ids.partner_a, "slack")  # only slack verified

        r1 = workflows.clone_template(db, ids.partner_a, tid, ids.company_a, "wf1")
        assert not r1.ok
        assert r1.missing_connectors == ["gmail"]
        assert db.execute(text("SELECT count(*) FROM workflows")).scalar_one() == 0  # nothing written

        connectors.verify_connector(db, ids.partner_a, "gmail")
        r2 = workflows.clone_template(db, ids.partner_a, tid, ids.company_a, "wf1")
        assert r2.ok
        wf = db.execute(text(
            "SELECT definition, status, template_id FROM workflows WHERE id = :w"),
            {"w": str(r2.workflow_id)}).one()
    assert wf.status == "draft"
    assert wf.definition == {"steps": [1, 2]}   # copied from the template
    assert wf.template_id == tid


def test_cannot_clone_another_partners_template(ids, platform_engine, partner_orm):
    tid = uuid.uuid4()
    with platform_engine.begin() as c:  # commit a template owned by partner A
        c.execute(text(
            "INSERT INTO workflow_templates (id, partner_id, name) VALUES (:id, :p, 'A only')"),
            {"id": str(tid), "p": str(ids.partner_a)})
    with partner_orm(ids.partner_b) as db:  # partner B can't even see it -> not found
        with pytest.raises(ValueError):
            workflows.clone_template(db, ids.partner_b, tid, ids.company_b, "steal")
