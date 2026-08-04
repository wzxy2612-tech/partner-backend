-- Runs once on first container init, as the postgres superuser, against
-- POSTGRES_DB (partner_backend). Establishes the four-role privilege model.
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

-- Anything app_owner creates later (via migrations) is born UNGRANTED: this
-- script deliberately does not create any default privileges. A table is born
-- unreachable, and every role that must touch it is granted explicitly in the
-- migration that creates it. (For historical clusters, migration 0020 serves
-- as the backfill that explicitly revoked all legacy default privileges).
