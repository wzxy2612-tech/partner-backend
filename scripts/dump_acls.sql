-- scripts/dump_acls.sql
--
-- public schema 里所有 app_* / PUBLIC 的表级与列级授权,排序后逐行输出。
-- 用途是 diff,不是阅读:B 方案的规格 = 两次快照的差集。
-- 排除 owner 自授权(任何显式 ACL 都带它,不是决定)。
--
--   docker compose exec -T db sh -c \
--     'psql -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' \
--     < scripts/dump_acls.sql > acl_<label>.txt

\pset format unaligned
\pset tuples_only on
\pset fieldsep '|'
\pset pager off

WITH tbl AS (
    SELECT c.relkind::text                AS kind,
           c.relname                      AS obj,
           ''                             AS col,
           COALESCE(g.rolname, 'PUBLIC')  AS grantee,
           a.privilege_type               AS priv
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN LATERAL aclexplode(c.relacl) AS a
    LEFT JOIN pg_roles g ON g.oid = a.grantee
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
      AND (g.rolname IS NULL OR starts_with(g.rolname, 'app_'))
      AND a.grantee IS DISTINCT FROM c.relowner
),
col AS (
    SELECT c.relkind::text,
           c.relname,
           att.attname,
           COALESCE(g.rolname, 'PUBLIC'),
           a.privilege_type
    FROM pg_class c
    JOIN pg_namespace n  ON n.oid = c.relnamespace
    JOIN pg_attribute att ON att.attrelid = c.oid
                          AND att.attnum > 0
                          AND NOT att.attisdropped
    CROSS JOIN LATERAL aclexplode(att.attacl) AS a
    LEFT JOIN pg_roles g ON g.oid = a.grantee
    WHERE n.nspname = 'public'
      AND (g.rolname IS NULL OR starts_with(g.rolname, 'app_'))
      AND a.grantee IS DISTINCT FROM c.relowner
)
SELECT kind, obj, col, grantee, priv FROM tbl
UNION ALL
SELECT * FROM col
ORDER BY 1, 2, 3, 4, 5;
