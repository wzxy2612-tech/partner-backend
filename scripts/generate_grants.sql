-- scripts/generate_grants.sql
--
-- 把活库的 ACL 反向渲染成 GRANT 语句。输出直接粘进 0020。
-- 不要手抄 —— 16 张表 × 2 角色 × 4 权限 + 列级例外,手抄一定会错一处,
-- 而错的那一处会是安静的(多授一个权限没有任何东西会响)。

\pset format unaligned
\pset tuples_only on
\pset pager off

-- 表级与序列级
SELECT format('GRANT %s ON %I TO %I;',
              string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type),
              c.relname,
              g.rolname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) AS a
JOIN pg_roles g ON g.oid = a.grantee          -- PUBLIC 不在此渲染,见下
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
  AND starts_with(g.rolname, 'app_')
  AND a.grantee IS DISTINCT FROM c.relowner
GROUP BY c.relname, g.rolname
ORDER BY c.relname, g.rolname;

-- 列级(0015 / 0018 / 0019 的产物)
SELECT format('GRANT %s (%s) ON %I TO %I;',
              a.privilege_type,
              string_agg(quote_ident(att.attname), ', ' ORDER BY att.attnum),
              c.relname,
              g.rolname)
FROM pg_class c
JOIN pg_namespace n   ON n.oid = c.relnamespace
JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum > 0 AND NOT att.attisdropped
CROSS JOIN LATERAL aclexplode(att.attacl) AS a
JOIN pg_roles g ON g.oid = a.grantee
WHERE n.nspname = 'public'
  AND starts_with(g.rolname, 'app_')
  AND a.grantee IS DISTINCT FROM c.relowner
GROUP BY c.relname, g.rolname, a.privilege_type
ORDER BY c.relname, g.rolname, a.privilege_type;

-- 若 dump_acls.sql 的输出里出现 grantee=PUBLIC,本脚本会漏掉它。
-- 那种情况不该用 GRANT 补,该单独查它从哪来。
