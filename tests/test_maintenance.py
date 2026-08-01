"""Retention/archival sweeps: purge expired suspensions, archive old threads."""
from sqlalchemy import text

from app.services import maintenance


def test_purge_only_removes_expired_suspensions(ids, platform_orm):
    with platform_orm() as db:
        # A: suspended but retention still in the future -> keep
        db.execute(text(
            "UPDATE partners SET status='suspended', "
            "suspension_retention_until = now() + make_interval(days => 30) WHERE id = :p"),
            {"p": str(ids.partner_a)})
        # B: suspended and retention window passed -> purge
        db.execute(text(
            "UPDATE partners SET status='suspended', "
            "suspension_retention_until = now() - make_interval(days => 1) WHERE id = :p"),
            {"p": str(ids.partner_b)})

        purged = maintenance.purge_expired_suspensions(db)
        remaining = {r for (r,) in db.execute(text("SELECT id FROM partners"))}
    assert ids.partner_b in purged and ids.partner_a not in purged
    assert ids.partner_a in remaining and ids.partner_b not in remaining


def test_purge_cascades_partner_children(ids, platform_orm):
    with platform_orm() as db:
        db.execute(text(
            "UPDATE partners SET status='suspended', "
            "suspension_retention_until = now() - make_interval(days => 1) WHERE id = :p"),
            {"p": str(ids.partner_b)})
        maintenance.purge_expired_suspensions(db)
        companies_b = db.execute(text(
            "SELECT count(*) FROM companies WHERE partner_id = :p"),
            {"p": str(ids.partner_b)}).scalar_one()
        users_b = db.execute(text(
            "SELECT count(*) FROM users WHERE partner_id = :p"),
            {"p": str(ids.partner_b)}).scalar_one()
    assert companies_b == 0 and users_b == 0  # cascaded away


def test_archive_marks_only_old_threads(ids, platform_orm):
    with platform_orm() as db:
        db.execute(text(
            "INSERT INTO threads (partner_id, company_id, subject, created_at) "
            "VALUES (:p, :c, 'old', now() - make_interval(days => 400))"),
            {"p": str(ids.partner_a), "c": str(ids.company_a)})
        db.execute(text(
            "INSERT INTO threads (partner_id, company_id, subject, created_at) "
            "VALUES (:p, :c, 'recent', now())"),
            {"p": str(ids.partner_a), "c": str(ids.company_a)})

        n = maintenance.archive_expired_threads(db, older_than_days=365)
        archived = db.execute(text(
            "SELECT subject FROM threads WHERE archived_at IS NOT NULL")).scalars().all()
        live = db.execute(text(
            "SELECT subject FROM threads WHERE archived_at IS NULL")).scalars().all()
    assert n == 1
    assert archived == ["old"] and live == ["recent"]
