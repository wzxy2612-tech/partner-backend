-- Independent confirmation that 0009 landed correctly.
--
-- Run against the container DB as the OWNER role (the one migrations use), so
-- that any RLS still in force applies -- if the platform row were only visible
-- with BYPASSRLS this would surface it:
--
--   docker compose exec db psql -U app_owner -d partner_backend -f /dev/stdin < verify_0009.sql
--
-- or paste it into:  docker compose exec db psql -U app_owner -d partner_backend
--
-- Owner is subject to partners' FORCE policy, so set the scope the same way the
-- migration did before reading the row back.
SET app.partner_id = '00000000-0000-0000-0000-000000000000';

\echo '--- 1. the platform row exists and is visible under its own scope ---'
SELECT id, name, status
FROM partners
WHERE id = '00000000-0000-0000-0000-000000000000';
-- expect exactly one row: Platform / active

\echo '--- 2. partners is STILL enable+force (the fix did not weaken it) ---'
SELECT relname,
       relrowsecurity  AS enabled,
       relforcerowsecurity AS forced
FROM pg_class
WHERE relname = 'partners';
-- expect: enabled = t, forced = t

\echo '--- 3. users and sessions now have a partner FK (0009 closed the gap) ---'
SELECT conrelid::regclass AS child, conname
FROM pg_constraint
WHERE contype = 'f'
  AND conrelid::regclass::text IN ('users', 'sessions')
  AND conname IN ('fk_users_partner', 'fk_sessions_partner')
ORDER BY child;
-- expect both rows

\echo '--- 4. the platform tenant is undeletable (trigger present + fires) ---'
SELECT tgname
FROM pg_trigger
WHERE tgrelid = 'partners'::regclass
  AND tgname = 'trg_protect_platform_tenant';
-- expect one row

\echo '--- 5. no partner_id column is left without a backing FK ---'
SELECT c.relname AS table_without_partner_fk
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
     AND a.attname = 'partner_id' AND a.attnum > 0 AND NOT a.attisdropped
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND NOT EXISTS (
    SELECT 1 FROM pg_constraint fk
    WHERE fk.conrelid = c.oid AND fk.contype = 'f' AND a.attnum = ANY (fk.conkey)
  );
-- expect zero rows
