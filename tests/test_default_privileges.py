"""tests/test_default_privileges.py

0020 的三条断言,分工是你一贯的那条:
  - 静态那条抓记账错误(有人又加了一条默认权限)
  - 探针那条抓设计错误(闸门根本没生效)
  - 探针清理那条确保不留残骸

只有探针能证明闸门存在。静态那条现在其实是空转(因为默认权限的真来源是 db/init),真正的守卫是 verify_fixes.py 的 R16。

fixture 名按你的 conftest 改:owner_engine = 以 app_owner 连,runtime_engine = 以 app_runtime 连。
"""

import pytest
from sqlalchemy import text

PROBE = "_defacl_probe"


def _sqlstate(exc) -> str | None:
    orig = getattr(exc, "orig", exc)
    return getattr(orig, "sqlstate", None)


def test_no_default_privileges_for_app_roles_or_public(owner_engine):
    """记账:审计视图必须为空。

    谓词故意不写在这里 —— 它在 0020 建的 audit_default_privileges 里,
    postflight 读的是同一个视图。在测试里重写一遍等价查询,
    就是给"什么算违规"造第二个裁决者。
    """
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT grantor, schema_name, objtype, "
                "COALESCE(grantee, 'PUBLIC') AS grantee, privilege_type "
                "FROM audit_default_privileges ORDER BY 1, 4"
            )
        ).all()
    assert rows == [], f"default privileges present: {rows}"


def test_new_table_is_born_without_runtime_access(owner_engine, runtime_engine):
    """行为:app_owner 新建的表,app_runtime 一个语句都跑不通。

    这是本轮唯一真正证明闸门存在的断言。0020 按构造对所有既有表不可见
    (默认权限只作用于其设立之后创建的对象),所以现存 208 条测试
    结构上无法覆盖它 —— 必须现造一张表。

    探针表必须由 app_owner 建:默认权限按 grantor 登记,换个角色建就不是同一条路径。
    """
    with owner_engine.connect() as oconn:
        oconn.execute(text(f"CREATE TABLE {PROBE} (id integer PRIMARY KEY)"))
        oconn.commit()
        try:
            for stmt in (
                f"SELECT 1 FROM {PROBE}",
                f"INSERT INTO {PROBE} (id) VALUES (1)",
                f"UPDATE {PROBE} SET id = 2",
                f"DELETE FROM {PROBE}",
            ):
                with pytest.raises(Exception) as exc:
                    with runtime_engine.connect() as rconn:
                        rconn.execute(text(stmt))
                # 42501 在这里没有归因歧义:表上根本没有 policy,
                # 不存在"是权限拒绝还是 RLS 拒绝"的问题。
                assert _sqlstate(exc.value) == "42501", f"{stmt} -> {exc.value!r}"
        finally:
            oconn.execute(text(f"DROP TABLE IF EXISTS {PROBE}"))
            oconn.commit()


def test_probe_table_left_no_residue(owner_engine):
    """探针进程被 kill 会留下一张裸表,而它对 grant-driven 覆盖率守卫不可见
    (无 grant → 不进枚举),所以不会有别的测试替你发现它。"""
    with owner_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT to_regclass(:n)"), {"n": f"public.{PROBE}"}
            ).scalar()
            is None
        )
