-- Create app_dispatcher on a database that already exists.
--
-- RUN AS A SUPERUSER, BEFORE MIGRATING TO 0018:
--   docker compose exec -T db psql -U postgres -d partner_backend \
--     < scripts/provision_dispatcher_role.sql
--
-- WHY THIS IS NOT A MIGRATION
--
-- app_owner is NOCREATEROLE, and that is on purpose. A migration is code that
-- runs automatically on deploy; if it could mint login roles, then "review the
-- schema change" and "review who can now connect to the database" would be the
-- same review, done by whoever was looking at a column rename. Creating a
-- principal is an operator action and stays one.
--
-- 0018 therefore checks that this role exists and refuses to run if it does
-- not, naming this file. It grants the role its (narrow) access; it does not
-- bring the role into being.
--
-- db/init/00-roles.sql does the same for a fresh volume. This file exists
-- because that one runs only on first container init, so an existing database
-- never sees it.
--
-- The password here matches the development default in db/init. That is the
-- same pre-existing deployment risk the audit already flagged for the other
-- three roles -- fixed credentials in the repository are fine for a local
-- topology and are not a production posture. A real deployment sets it from a
-- secret manager and this file is a template.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_dispatcher') THEN
    CREATE ROLE app_dispatcher LOGIN PASSWORD 'dispatcher_pw'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    RAISE NOTICE 'created role app_dispatcher';
  ELSE
    RAISE NOTICE 'role app_dispatcher already exists; leaving it alone';
  END IF;
END
$$;

-- Idempotent, and stated separately from creation so that re-running this file
-- repairs a role that exists with the wrong attributes rather than skipping it.
--
-- NOBYPASSRLS is the load-bearing one. A dispatcher with BYPASSRLS would not
-- FAIL any of the isolation tests -- it would make them vacuous, since row
-- security simply would not apply to it. 0018 refuses to run against such a
-- role, and tests/test_rls_coverage.py pins the set of bypassing roles.
ALTER ROLE app_dispatcher NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

GRANT USAGE ON SCHEMA public TO app_dispatcher;

\echo 'app_dispatcher provisioned. It has USAGE on the schema and nothing else;'
\echo 'migration 0018 grants the three tables it needs, one at a time.'
