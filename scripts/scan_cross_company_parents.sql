-- Cross-company workspace parent links: read-only pre-scan for migration 0012.
--
-- Run this BEFORE attempting `alembic upgrade` to 0012. The migration refuses to
-- apply while any of these exist, deliberately -- detaching or re-homing a
-- workspace changes hierarchy and branding inheritance, so the decision belongs
-- to an operator, not to a migration. This script only reports.
--
--   docker compose exec -T db psql -U app_owner -d partner_backend \
--     -f /dev/stdin < scripts/scan_cross_company_parents.sql
--
-- Runs as the owner. `workspaces` has FORCE row security, so set the tenant GUC
-- to NULL semantics first: with no scope set, the policy matches no rows. Use
-- the platform role instead if you need to see across tenants:
--
--   docker compose exec -T db psql -U app_platform -d partner_backend \
--     -f /dev/stdin < scripts/scan_cross_company_parents.sql
--
-- app_platform holds BYPASSRLS, which is what makes a cross-tenant audit
-- possible at all.

\echo '--- 1. offending parent links (the migration blocks on these) ---'
SELECT c.partner_id,
       c.id            AS child_workspace_id,
       c.name          AS child_name,
       c.company_id    AS child_company_id,
       p.id            AS parent_workspace_id,
       p.name          AS parent_name,
       p.company_id    AS parent_company_id
FROM workspaces c
JOIN workspaces p ON p.id = c.parent_workspace_id
WHERE c.company_id IS DISTINCT FROM p.company_id
ORDER BY c.partner_id, c.company_id, c.id;

\echo ''
\echo '--- 2. how many, per partner ---'
SELECT c.partner_id, count(*) AS offending_links
FROM workspaces c
JOIN workspaces p ON p.id = c.parent_workspace_id
WHERE c.company_id IS DISTINCT FROM p.company_id
GROUP BY c.partner_id
ORDER BY offending_links DESC;

\echo ''
\echo '--- 3. blast radius: descendants that inherit a wrong company scope ---'
-- A bad link contaminates everything BELOW it too, because scope resolution
-- walks to the root. This counts the full subtree under each offending child,
-- which is the real number of workspaces currently resolving to the wrong
-- company for authorization and branding.
WITH RECURSIVE bad AS (
    SELECT c.id, c.partner_id, c.company_id
    FROM workspaces c
    JOIN workspaces p ON p.id = c.parent_workspace_id
    WHERE c.company_id IS DISTINCT FROM p.company_id
),
subtree AS (
    SELECT b.id AS root_id, w.id, w.partner_id, w.company_id, 0 AS depth
    FROM bad b JOIN workspaces w ON w.id = b.id
    UNION ALL
    SELECT s.root_id, w.id, w.partner_id, w.company_id, s.depth + 1
    FROM subtree s
    JOIN workspaces w ON w.parent_workspace_id = s.id
    WHERE s.depth < 32          -- same ceiling as MAX_SCOPE_DEPTH
)
SELECT root_id AS offending_child, count(*) AS affected_workspaces, max(depth) AS subtree_depth
FROM subtree
GROUP BY root_id
ORDER BY affected_workspaces DESC;

\echo ''
\echo '--- 4. candidate same-company parents, to help reattach ---'
-- For each offending child, the workspaces in ITS OWN company that could
-- legitimately serve as a parent. A child with no candidate here can only be
-- detached to a root or re-homed.
SELECT c.id AS child_workspace_id,
       count(cand.id) AS candidate_parents_in_own_company
FROM workspaces c
JOIN workspaces p ON p.id = c.parent_workspace_id
LEFT JOIN workspaces cand
       ON cand.partner_id = c.partner_id
      AND cand.company_id = c.company_id
      AND cand.id <> c.id
WHERE c.company_id IS DISTINCT FROM p.company_id
GROUP BY c.id
ORDER BY candidate_parents_in_own_company;
