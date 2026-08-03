-- Runs once on first container init, as the postgres superuser, against
-- POSTGRES_DB (partner_backend). Establishes the three-role privilege model.
--
--   app_owner    -> owns schema objects, runs migrations (DDL). Never used at
--                   request time.
--   app_runtime  -> partner-facing request path. NOBYPASSRLS -> always subject
--                   to RLS. Never has DDL.
--   app_platform -> direct-customer / platform-admin / Stripe-webhook path.
--                   BYPASSRLS -> behaves like the pre-existing app.
--   app_dispatcher -> outbox delivery only. NOBYPASSRLS. Sees other tenants'
--                   rows through three narrow policies granted in 0018, not
--                   through a role attribute -- so the reach is per table and
--                   auditable, and adding a table does not widen it.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_owner') THEN
    CREATE ROLE app_owner LOGIN PASSWORD 'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime LOGIN PASSWORD 'runtime_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_platform') THEN
    CREATE ROLE app_platform LOGIN PASSWORD 'platform_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_dispatcher') THEN
    CREATE ROLE app_dispatcher LOGIN PASSWORD 'dispatcher_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;

ALTER DATABASE partner_backend OWNER TO app_owner;

\connect partner_backend

ALTER SCHEMA public OWNER TO app_owner;
GRANT USAGE ON SCHEMA public TO app_runtime, app_platform, app_dispatcher;

-- Anything app_owner creates later (via migrations) is automatically usable by
-- the two runtime roles -> no per-table GRANTs needed in migrations.
--
-- app_dispatcher is DELIBERATELY ABSENT from these default privileges. This is
-- the mechanism that made outbox_events world-writable the day 0013 created it:
-- a new table is granted before anyone decides whether it should be. The newest
-- role does not inherit that. It starts with nothing and every table it can
-- reach was granted on purpose, in a migration, one at a time.
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime, app_platform;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app_runtime, app_platform;
