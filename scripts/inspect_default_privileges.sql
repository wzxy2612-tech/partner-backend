-- scripts/inspect_default_privileges.sql
--
-- 0020 的前置诊断。只读,superuser 或 app_owner 均可运行。
-- 目的:确认"新表出生即全租户可写"的来源。三段分别对应三种可能的来源,
-- 三段都空 = 假设被证伪,0020 只是 pin 而不是 fix,真来源还没找到。
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/inspect_default_privileges.sql

\echo ''
\echo '=== 1. pg_default_acl:显式登记的默认权限 ==='
\echo '    can_revoke=false 的条目 0020 改不动(ALTER DEFAULT PRIVILEGES FOR ROLE x'
\echo '    需要 x 的成员资格),必须回到它被创建的地方修 —— db/init 或 provision 脚本。'
\echo ''

SELECT
    gr.rolname                                AS grantor,
    COALESCE(n.nspname, '<all schemas>')      AS schema_name,
    CASE d.defaclobjtype
        WHEN 'r' THEN 'TABLES'
        WHEN 'S' THEN 'SEQUENCES'
        WHEN 'f' THEN 'FUNCTIONS'
        WHEN 'T' THEN 'TYPES'
        WHEN 'n' THEN 'SCHEMAS'
        ELSE d.defaclobjtype::text
    END                                       AS objtype,
    COALESCE(g.rolname, 'PUBLIC')             AS grantee,
    a.privilege_type,
    pg_has_role('app_owner', d.defaclrole, 'USAGE') AS can_revoke_from_migration
FROM pg_default_acl d
JOIN pg_roles gr        ON gr.oid = d.defaclrole
LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
CROSS JOIN LATERAL aclexplode(d.defaclacl) AS a
LEFT JOIN pg_roles g    ON g.oid = a.grantee
-- 排除 owner 对自己的隐含自授权:任何显式 ACL 都带着它,不是发现。
WHERE a.grantee IS DISTINCT FROM d.defaclrole
ORDER BY 1, 2, 3, 4, 5;


\echo ''
\echo '=== 2. 角色继承:app_* 是否是别人的成员 ==='
\echo '    如果 app_runtime 继承 app_owner,那它对每张新表都有 owner 权限,'
\echo '    此刻挡住它的只有 FORCE ROW LEVEL SECURITY —— 而 grant 层是敞开的。'
\echo '    这种情况下 0020 无效,修法是撤销 membership,不是撤销默认权限。'
\echo ''

SELECT
    m.rolname          AS member,
    r.rolname          AS member_of,
    m.rolinherit       AS member_role_inherits,
    mem.admin_option
FROM pg_auth_members mem
JOIN pg_roles m ON m.oid = mem.member
JOIN pg_roles r ON r.oid = mem.roleid
WHERE starts_with(m.rolname, 'app_')
   OR starts_with(r.rolname, 'app_')
ORDER BY 1, 2;
-- PG16 起 membership 自带 inherit_option / set_option,若上表非空再查:
--   SELECT * FROM pg_auth_members WHERE member::regrole::text LIKE 'app%';


\echo ''
\echo '=== 3. 谁在建对象:决定未来对象的 grantor 是谁 ==='
\echo '    第 1 段只对这里出现过的 owner 有意义。若这里有 app_owner 之外的角色,'
\echo '    说明有第二条建表路径(db/init?provision?),它的默认权限要单独查。'
\echo ''

SELECT
    c.relowner::regrole::text AS owner,
    c.relkind,
    count(*) AS n
FROM pg_class c
JOIN pg_namespace nc ON nc.oid = c.relnamespace
WHERE nc.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
GROUP BY 1, 2
ORDER BY 1, 2;
