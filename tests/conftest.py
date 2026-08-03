import os
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as OrmSession, sessionmaker
from alembic.config import Config
from alembic import command

from app.auth.password import hash_password

# The test keyring, injected here rather than defaulted inside the library.
#
# outbox_crypto has no fallback key any more: it used to mint a fixed all-zero
# one whenever OUTBOX_KEYS was unset, which is what made `make up` encrypt real
# invitation tokens under a key printed in this repository. Putting the test key
# here keeps the suite self-contained AND keeps the deployment honest -- compose
# has to be given a real one, because nothing will invent it.
#
# Set before any app module reads it. _keyring() resolves lazily at call time,
# so import order does not matter, but the value must be in place before the
# first encrypt.
os.environ.setdefault("OUTBOX_KEYS", "1:" + "11" * 32)

OWNER_URL = os.environ.get(
    "OWNER_DATABASE_URL", "postgresql+psycopg://app_owner:owner_pw@localhost:5432/partner_backend")
RUNTIME_URL = os.environ.get(
    "RUNTIME_DATABASE_URL", "postgresql+psycopg://app_runtime:runtime_pw@localhost:5432/partner_backend")
PLATFORM_URL = os.environ.get(
    "PLATFORM_DATABASE_URL", "postgresql+psycopg://app_platform:platform_pw@localhost:5432/partner_backend")
# The delivery role (0018). Present here only so its boundary can be asserted --
# proving app_dispatcher may not redirect an event requires connecting as it.
DISPATCHER_URL = os.environ.get(
    "DISPATCHER_DATABASE_URL", "postgresql+psycopg://app_dispatcher:dispatcher_pw@localhost:5432/partner_backend")

PARTNER_A = UUID("11111111-1111-1111-1111-111111111111")
PARTNER_B = UUID("22222222-2222-2222-2222-222222222222")
COMPANY_A = UUID("aaaaaaaa-0000-0000-0000-000000000001")
COMPANY_B = UUID("bbbbbbbb-0000-0000-0000-000000000001")
COMPANY_A2 = UUID("aaaaaaaa-0000-0000-0000-000000000002")
WORKSPACE_A_PARENT = UUID("aaaaaaaa-0000-0000-0000-0000000000a1")
WORKSPACE_A_CHILD = UUID("aaaaaaaa-0000-0000-0000-0000000000a2")
WORKSPACE_B = UUID("bbbbbbbb-0000-0000-0000-0000000000b2")
USER_A = UUID("aaaaaaaa-0000-0000-0000-0000000000d1")
USER_B = UUID("bbbbbbbb-0000-0000-0000-0000000000b1")
USER_CA = UUID("aaaaaaaa-0000-0000-0000-0000000000ca")   # company_admin @ Company A
USER_RO = UUID("aaaaaaaa-0000-0000-0000-0000000000e0")   # read_only @ Company A
DIRECT_USER = UUID("cccccccc-0000-0000-0000-0000000000c1")
PLATFORM_ADMIN = UUID("cccccccc-0000-0000-0000-0000000000f1")
NIL = UUID("00000000-0000-0000-0000-000000000000")

PW_A = "pw-a-secret"
PW_DIRECT = "pw-direct-secret"
PW_CA = "pw-ca-secret"
PW_PLATFORM = "pw-platform-secret"


@pytest.fixture(scope="session", autouse=True)
def _migrate():
    command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture(scope="session")
def platform_engine():
    eng = create_engine(PLATFORM_URL)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def dispatcher_engine():
    """The delivery role (0018): NOBYPASSRLS, three tables, nothing else.

    Its cross-tenant reach comes from three `USING (true)` policies rather than
    the role attribute -- which is a real difference and also a smaller one than
    it sounds, so tests that use this fixture should be asserting a boundary,
    not borrowing a convenient connection.
    """
    eng = create_engine(DISPATCHER_URL)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def owner_engine():
    """Owner connection -- the only role that can ALTER TABLE.

    Exists solely so a test can construct data that PREDATES a constraint, by
    dropping it inside a rolled-back savepoint. Nothing else should use this:
    every other test must run as app_runtime or app_platform, because those are
    the roles the application actually holds, and a test that quietly runs as
    owner proves less than it appears to."""
    eng = create_engine(OWNER_URL)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def runtime_engine():
    eng = create_engine(RUNTIME_URL)
    yield eng
    eng.dispose()


@pytest.fixture()
def ids(platform_engine):
    """Seed two partners, each with a company / workspace(s) / user / activity
    row, plus one direct customer. USER_A is a Partner Super Admin at partner
    scope and has a password; the direct user has a password too. Seeded as
    app_platform (BYPASSRLS); re-seeded per test."""
    pw_a = hash_password(PW_A)
    pw_direct = hash_password(PW_DIRECT)
    pw_ca = hash_password(PW_CA)
    pw_platform = hash_password(PW_PLATFORM)
    with platform_engine.begin() as c:
        for tbl in ["invitations", "partner_activity_log", "sessions", "memberships",
                    "workflows", "workflow_templates", "connectors", "token_usage",
                    "threads", "workspaces", "companies", "subscriptions", "users",
                    "partners"]:
            if tbl == "partners":
                # The platform tenant is schema, not fixture data: users and
                # sessions FK to it and a trigger refuses its deletion.
                c.execute(text("DELETE FROM partners WHERE id <> :nil"), {"nil": str(NIL)})
            else:
                c.execute(text(f"DELETE FROM {tbl}"))
        c.execute(text(
            "INSERT INTO partners (id,name,status) "
            "VALUES (:a,'Partner A','active'),(:b,'Partner B','active')"),
            {"a": str(PARTNER_A), "b": str(PARTNER_B)})
        c.execute(text(
            "INSERT INTO companies (id,partner_id,name,branding) VALUES "
            "(:ca,:a,'Company A','{\"color\":\"navy\",\"logo\":\"co-a\"}'::jsonb),"
            "(:cb,:b,'Company B','{}'::jsonb)"),
            {"ca": str(COMPANY_A), "a": str(PARTNER_A), "cb": str(COMPANY_B), "b": str(PARTNER_B)})
        c.execute(text("INSERT INTO companies (id,partner_id,name,branding) "
                       "VALUES (:ca2,:a,'Company A2','{}'::jsonb)"),
                  {"ca2": str(COMPANY_A2), "a": str(PARTNER_A)})
        c.execute(text(
            "INSERT INTO workspaces (id,partner_id,company_id,parent_workspace_id,name,branding) VALUES "
            "(:wp,:a,:ca,NULL,'Hub A','{\"logo\":\"hub-a\"}'::jsonb),"
            "(:wc,:a,:ca,:wp,'Child A','{}'::jsonb),"
            "(:wb,:b,:cb,NULL,'Hub B','{}'::jsonb)"),
            {"wp": str(WORKSPACE_A_PARENT), "wc": str(WORKSPACE_A_CHILD), "wb": str(WORKSPACE_B),
             "a": str(PARTNER_A), "b": str(PARTNER_B), "ca": str(COMPANY_A), "cb": str(COMPANY_B)})
        c.execute(text(
            "INSERT INTO users (id,email,hashed_password,partner_id,billing_source) VALUES "
            "(:ua,'a@partner.test',:pwa,:a,'partner'),"
            "(:ub,'b@partner.test',NULL,:b,'partner'),"
            "(:ud,'direct@customer.test',:pwd,:nil,'stripe')"),
            {"ua": str(USER_A), "pwa": pw_a, "a": str(PARTNER_A),
             "ub": str(USER_B), "b": str(PARTNER_B),
             "ud": str(DIRECT_USER), "pwd": pw_direct, "nil": str(NIL)})
        c.execute(text(
            "INSERT INTO users (id,email,hashed_password,partner_id,billing_source) VALUES "
            "(:uca,'ca@partner.test',:pwca,:a,'partner'),"
            "(:uro,'ro@partner.test',NULL,:a,'partner')"),
            {"uca": str(USER_CA), "pwca": pw_ca, "uro": str(USER_RO), "a": str(PARTNER_A)})
        c.execute(text(
            "INSERT INTO users (id,email,hashed_password,partner_id,billing_source) "
            "VALUES (:up,'ops@platform.test',:pwp,:nil,'partner')"),
            {"up": str(PLATFORM_ADMIN), "pwp": pw_platform, "nil": str(NIL)})
        c.execute(text(
            "INSERT INTO memberships (user_id,partner_id,scope_type,scope_id,role) "
            "VALUES (:up,:nil,'platform',:nil,'platform_super_admin')"),
            {"up": str(PLATFORM_ADMIN), "nil": str(NIL)})
        c.execute(text(
            "INSERT INTO memberships (user_id,partner_id,scope_type,scope_id,role) "
            "VALUES (:ua,:a,'partner',:a,'partner_super_admin')"),
            {"ua": str(USER_A), "a": str(PARTNER_A)})
        c.execute(text(
            "INSERT INTO memberships (user_id,partner_id,scope_type,scope_id,role) VALUES "
            "(:uca,:a,'company',:ca,'company_admin'),"
            "(:uro,:a,'company',:ca,'read_only')"),
            {"uca": str(USER_CA), "uro": str(USER_RO), "a": str(PARTNER_A), "ca": str(COMPANY_A)})
        c.execute(text(
            "INSERT INTO partner_activity_log (partner_id,event_type) "
            "VALUES (:a,'partner.activated'),(:b,'partner.activated')"),
            {"a": str(PARTNER_A), "b": str(PARTNER_B)})
    return SimpleNamespace(
        partner_a=PARTNER_A, partner_b=PARTNER_B, company_a=COMPANY_A, company_b=COMPANY_B,
        workspace_a_parent=WORKSPACE_A_PARENT, workspace_a_child=WORKSPACE_A_CHILD,
        workspace_b=WORKSPACE_B, user_a=USER_A, user_b=USER_B, direct_user=DIRECT_USER,
        nil=NIL, pw_a=PW_A, pw_direct=PW_DIRECT,
        company_a2=COMPANY_A2, user_ca=USER_CA, user_ro=USER_RO, pw_ca=PW_CA,
        platform_admin=PLATFORM_ADMIN, pw_platform=PW_PLATFORM)


@pytest.fixture()
def partner_ctx(runtime_engine):
    """Raw runtime Connection scoped to a partner (or None for 'no context').
    Rolled back afterwards so tests never mutate the seed."""
    @contextmanager
    def _ctx(partner_id):
        conn = runtime_engine.connect()
        trans = conn.begin()
        try:
            if partner_id is not None:
                conn.execute(text("SELECT set_config('app.partner_id', :pid, true)"),
                             {"pid": str(partner_id)})
            yield conn
        finally:
            trans.rollback()
            conn.close()
    return _ctx


@pytest.fixture()
def platform_ctx(platform_engine):
    @contextmanager
    def _ctx():
        conn = platform_engine.connect()
        trans = conn.begin()
        try:
            yield conn
        finally:
            trans.rollback()
            conn.close()
    return _ctx


@pytest.fixture()
def platform_orm(platform_engine):
    """ORM Session on the platform path (BYPASSRLS), rolled back afterwards."""
    Maker = sessionmaker(bind=platform_engine, expire_on_commit=False)
    @contextmanager
    def _ctx():
        conn = platform_engine.connect()
        trans = conn.begin()
        sess: OrmSession = Maker(bind=conn)
        try:
            yield sess
        finally:
            sess.close()
            trans.rollback()
            conn.close()
    return _ctx


@pytest.fixture()
def partner_orm(runtime_engine):
    """ORM Session on the runtime path scoped to a partner, rolled back after."""
    Maker = sessionmaker(bind=runtime_engine, expire_on_commit=False)
    @contextmanager
    def _ctx(partner_id):
        conn = runtime_engine.connect()
        trans = conn.begin()
        conn.execute(text("SELECT set_config('app.partner_id', :pid, true)"),
                     {"pid": str(partner_id)})
        sess: OrmSession = Maker(bind=conn)
        try:
            yield sess
        finally:
            sess.close()
            trans.rollback()
            conn.close()
    return _ctx
