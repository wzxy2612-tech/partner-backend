"""revoke default privileges and establish explicit ACL baseline

新对象出生时不带任何 app_* / PUBLIC 授权。想让 runtime 碰某张表,
必须在建表的同一个 migration 里显式 GRANT —— 此时 grant-driven 的
覆盖率守卫才看得见它,才会要求配套 policy。

这是闸门,不是检测器:根因 A 从"事后被 make test 抓到"变成"根本不产生"。

同时，此脚本也是现有 15 张以上业务表权限的显式文本基线。

Revision ID: 0020
Revises: 0019
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# downgrade 的输入。
#
#   (grantor, schema_or_None, objtype, grantee, privileges)
#   ("app_owner", "public", "TABLES", "app_runtime", "SELECT, INSERT, UPDATE, DELETE")
#
# 真实来源是 db/init/00-roles.sql，但那里的默认授权已经被删除。
# 这里的 downgrade() 是重建（Reconstruct）而非简单的还原，
# 因为 alembic 的可逆契约管不到未版本化的 db/init。
#
# 这里是手抄件:upgrade 是状态驱动(枚举实际存在的),downgrade 是声明驱动。
# 不对称是有意的 —— 反向恢复一个不知道内容的状态只能靠记录它,
# 而把撤销前的 ACL 存进一张表,是给同一个事实造第二个裁决者。
# ---------------------------------------------------------------------------
PRIOR_STATE: list[tuple[str, str | None, str, str, str]] = [
    ("app_owner", "public", "TABLES",    "app_runtime",  "SELECT, INSERT, UPDATE, DELETE"),
    ("app_owner", "public", "TABLES",    "app_platform", "SELECT, INSERT, UPDATE, DELETE"),
    ("app_owner", "public", "SEQUENCES", "app_runtime",  "USAGE, SELECT"),
    ("app_owner", "public", "SEQUENCES", "app_platform", "USAGE, SELECT"),
]


AUDIT_VIEW = """
CREATE OR REPLACE VIEW audit_default_privileges AS
SELECT
    d.defaclrole              AS grantor_oid,
    gr.rolname                AS grantor,
    n.nspname                 AS schema_name,   -- NULL = 所有 schema
    d.defaclobjtype           AS objtype,
    g.rolname                 AS grantee,       -- NULL = PUBLIC
    a.privilege_type
FROM pg_default_acl d
JOIN pg_roles gr         ON gr.oid = d.defaclrole
LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
CROSS JOIN LATERAL aclexplode(d.defaclacl) AS a
LEFT JOIN pg_roles g     ON g.oid = a.grantee
WHERE
    -- grantee 从 pg_roles 按前缀枚举,新建的 app_* 角色当天自动进范围。
    -- grantee IS NULL 即 PUBLIC:必须在内,否则 GRANT ... TO PUBLIC
    -- 会让每个角色拿到权限,而按 rolname 枚举的守卫一个都看不见。
    (g.rolname IS NULL OR starts_with(g.rolname, 'app_'))
    -- owner 对自己的自授权是任何显式 ACL 的固有部分,不是发现。
    -- 少了这条,"对 PUBLIC 撤 EXECUTE" 留下的负条目会被误报成违规。
    AND a.grantee IS DISTINCT FROM d.defaclrole;
"""

VIEW_COMMENT = """
COMMENT ON VIEW audit_default_privileges IS
'0020 的单一谓词。postflight 与 tests/test_default_privileges.py 都读它:'
'非空即违规。不要在别处重写这个查询 —— 两个独立回答同一问题的组件最终会分歧。'
'刻意不授予任何 app_* SELECT:一旦授予,grant-driven 覆盖率守卫会把它枚举进来,'
'而视图挂不了 policy。';
"""


REVOKE_ALL = """
DO $$
DECLARE
    rec         record;
    blocked     text[] := '{}';
    grantee_sql text;
    schema_sql  text;
    objtype_sql text;
    stmt        text;
BEGIN
    FOR rec IN
        SELECT DISTINCT grantor_oid, grantor, schema_name, objtype, grantee
        FROM audit_default_privileges
    LOOP
        -- ALTER DEFAULT PRIVILEGES FOR ROLE x 需要 x 的成员资格。
        -- 拿不到就登记,循环结束后整体失败 —— 不静默跳过。
        -- 一个跳过了却报成功的闸门,和没有闸门是同一件事,但更难发现。
        IF NOT pg_has_role(current_user, rec.grantor_oid, 'USAGE') THEN
            blocked := blocked || format('%s -> %s',
                rec.grantor, COALESCE(rec.grantee, 'PUBLIC'));
            CONTINUE;
        END IF;

        -- PUBLIC 是关键字,%I 会把它引号化成一个不存在的角色名。
        grantee_sql := CASE WHEN rec.grantee IS NULL
                            THEN 'PUBLIC'
                            ELSE quote_ident(rec.grantee) END;

        -- ON SCHEMAS 不接受 IN SCHEMA;schema_name IS NULL 亦然。
        schema_sql  := CASE WHEN rec.schema_name IS NULL OR rec.objtype = 'n'
                            THEN ''
                            ELSE format('IN SCHEMA %I ', rec.schema_name) END;

        objtype_sql := CASE rec.objtype
                            WHEN 'r' THEN 'TABLES'
                            WHEN 'S' THEN 'SEQUENCES'
                            WHEN 'f' THEN 'FUNCTIONS'
                            WHEN 'T' THEN 'TYPES'
                            WHEN 'n' THEN 'SCHEMAS'
                       END;

        IF objtype_sql IS NULL THEN
            RAISE EXCEPTION 'unhandled defaclobjtype % for grantor %',
                rec.objtype, rec.grantor;
        END IF;

        stmt := format('ALTER DEFAULT PRIVILEGES FOR ROLE %I %sREVOKE ALL ON %s FROM %s',
                       rec.grantor, schema_sql, objtype_sql, grantee_sql);
        RAISE NOTICE 'default-acl: %', stmt;
        EXECUTE stmt;
    END LOOP;

    IF array_length(blocked, 1) IS NOT NULL THEN
        RAISE EXCEPTION
            'default privileges exist under a grantor this migration cannot alter: %. '
            'ALTER DEFAULT PRIVILEGES FOR ROLE <x> requires membership in <x>; '
            'app_owner is not a member. Fix these where they were created '
            '(db/init or the provision script), then re-run.',
            array_to_string(blocked, ', ');
    END IF;
END
$$;
"""


POSTFLIGHT = """
DO $$
DECLARE
    leftovers text;
BEGIN
    SELECT string_agg(
               format('%s/%s %s -> %s:%s',
                      grantor, COALESCE(schema_name, '*'), objtype,
                      COALESCE(grantee, 'PUBLIC'), privilege_type),
               ', ' ORDER BY grantor, grantee)
    INTO leftovers
    FROM audit_default_privileges;

    IF leftovers IS NOT NULL THEN
        RAISE EXCEPTION 'postflight: default privileges survive: %', leftovers;
    END IF;
END
$$;
"""


def upgrade() -> None:
    op.execute(AUDIT_VIEW)
    op.execute(VIEW_COMMENT)
    op.execute("REVOKE ALL ON audit_default_privileges FROM app_runtime, app_platform")
    op.execute(REVOKE_ALL)
    op.execute(POSTFLIGHT)

    op.execute("""
        GRANT DELETE, INSERT, SELECT, UPDATE ON companies            TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON companies            TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON connectors           TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON connectors           TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON invitations          TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON invitations          TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON memberships          TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON memberships          TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON outbox_events        TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON partner_activity_log TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON partner_activity_log TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON partners             TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON sessions             TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON sessions             TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON subscriptions        TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON threads              TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON threads              TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON token_usage          TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON token_usage          TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON users                TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON users                TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workflow_templates   TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workflow_templates   TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workflows            TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workflows            TO app_runtime;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workspaces           TO app_platform;
        GRANT DELETE, INSERT, SELECT, UPDATE ON workspaces           TO app_runtime;

        -- Asymmetric Grants (Do NOT auto-complete)
        -- 1. partners: Read-only for app_runtime (writes go through DEFINER functions from 0015).
        GRANT SELECT ON partners TO app_runtime;

        -- 2. subscriptions: No app_runtime grants.
        -- Reason (from 0008): subscriptions has no RLS and no partner_id -- it predates tenancy 
        -- and belongs to the direct-customer Stripe path.
    """)


def downgrade() -> None:
    for grantor, schema_name, objtype, grantee, privileges in PRIOR_STATE:
        in_schema = f"IN SCHEMA {schema_name} " if schema_name else ""
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} {in_schema}"
            f"GRANT {privileges} ON {objtype} TO {grantee}"
        )
    op.execute("DROP VIEW IF EXISTS audit_default_privileges")
