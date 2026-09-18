"""POST /audit-lock 的端到端测试。

覆盖：有效锁、missing / unavailable / constraint_mismatch / extraneous
四类问题、环与菱形的约束累计、PEP 503 规范化、PEP 440 等价性、marker
语义复用、预发布开关、确定性排序，以及 422 映射。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}


def c(version, deps=None):
    return {"version": version, "dependencies": deps or []}


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def audit(repo, lock, *, env=None, **overrides):
    body = {
        "repository": repo,
        "root": "app",
        "target_environment": env or ENV,
        "current_lock": lock,
    }
    body.update(overrides)
    return client.post("/audit-lock", json=body)


# --------------------------------------------------------------------- #
# 1. 有效锁：valid=true 且 issues 为空
# --------------------------------------------------------------------- #
def test_audit_valid_lock():
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0"), d("liby")])],
        "libx": [c("1.0"), c("2.0")],
        "liby": [c("1.1"), c("0.9")],
    }
    lock = {"app": "1.0", "libx": "2.0", "liby": "1.1"}
    r = audit(repo, lock)
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}


def test_audit_lock_is_not_re_solved():
    """审计不重新求解：libx 锁 1.0 虽非最高候选，但满足约束即有效。"""
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0")])],
        "libx": [c("1.0"), c("2.0")],
    }
    r = audit(repo, {"app": "1.0", "libx": "1.0"})
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}
    # 对照：/resolve 在同一快照下会取最高版本 2.0
    resolved = client.post("/resolve", json={
        "repository": repo, "root": "app", "target_environment": ENV,
    })
    assert resolved.json()["locked"]["libx"] == "2.0"


def test_audit_valid_lock_with_cycle():
    """依赖环上的包只展开一次；所有入边约束均满足时有效。"""
    repo = {
        "app": [c("1.0", [d("a", ">=1.0")])],
        "a": [c("1.0", [d("b")])],
        "b": [c("1.0", [d("a", "<2.0")])],
    }
    r = audit(repo, {"app": "1.0", "a": "1.0", "b": "1.0"})
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}


# --------------------------------------------------------------------- #
# 2. missing：可达包未锁定
# --------------------------------------------------------------------- #
def test_audit_missing_dependency():
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0")])],
        "libx": [c("1.0")],
    }
    r = audit(repo, {"app": "1.0"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is False
    assert body["issues"] == [
        {
            "kind": "missing",
            "package": "libx",
            "locked_version": None,
            "constraints": [{"from": "app==1.0", "specifier": ">=1.0"}],
        }
    ]


def test_audit_missing_root():
    repo = {"app": [c("1.0")]}
    r = audit(repo, {"other": "1.0"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is False
    issues = {i["package"]: i for i in body["issues"]}
    assert issues["app"] == {
        "kind": "missing",
        "package": "app",
        "locked_version": None,
        "constraints": [{"from": "root", "specifier": "*"}],
    }
    # other 从根不可达 -> extraneous
    assert issues["other"]["kind"] == "extraneous"


def test_audit_missing_blocks_expansion_and_cascades_to_extraneous():
    """a 未锁定 -> 无法展开其依赖 -> 锁中的 b 不可达（extraneous）。"""
    repo = {
        "app": [c("1.0", [d("a")])],
        "a": [c("1.0", [d("b")])],
        "b": [c("1.0")],
    }
    r = audit(repo, {"app": "1.0", "b": "1.0"})
    assert r.status_code == 200, r.text
    kinds = {i["package"]: i["kind"] for i in r.json()["issues"]}
    assert kinds == {"a": "missing", "b": "extraneous"}


# --------------------------------------------------------------------- #
# 3. unavailable：锁定版本不在快照（PEP 440 等价性匹配）
# --------------------------------------------------------------------- #
def test_audit_unavailable_locked_version():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0")],
    }
    r = audit(repo, {"app": "1.0", "libx": "9.9"})
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "unavailable",
            "package": "libx",
            "locked_version": "9.9",
            "constraints": [{"from": "app==1.0", "specifier": "*"}],
        }
    ]


def test_audit_pep440_equivalent_version_is_available():
    """锁中 1.0 与快照 1.0.0 按 PEP 440 等价：可用且按其依赖展开。"""
    repo = {
        "app": [c("1.0.0", [d("libx")])],
        "libx": [c("1.0.0", [d("liby")])],
        "liby": [c("2.0.0")],
    }
    r = audit(repo, {"app": "1.0", "libx": "1.0", "liby": "2.0"})
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}


# --------------------------------------------------------------------- #
# 4. constraint_mismatch：锁定版本不满足根约束或依赖约束
# --------------------------------------------------------------------- #
def test_audit_constraint_mismatch_root_specifier():
    repo = {"app": [c("1.0"), c("2.0")]}
    r = audit(repo, {"app": "1.0"}, specifier=">=2.0")
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "constraint_mismatch",
            "package": "app",
            "locked_version": "1.0",
            "constraints": [{"from": "root", "specifier": ">=2.0"}],
        }
    ]


def test_audit_constraint_mismatch_dependency():
    repo = {
        "app": [c("1.0", [d("libx", ">=2.0")])],
        "libx": [c("1.0"), c("2.0")],
    }
    r = audit(repo, {"app": "1.0", "libx": "1.0"})
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "constraint_mismatch",
            "package": "libx",
            "locked_version": "1.0",
            "constraints": [{"from": "app==1.0", "specifier": ">=2.0"}],
        }
    ]


def test_audit_cycle_accumulates_all_incoming_constraints():
    """环：a 只展开一次，但 b 回边的约束仍计入 a 的判定。"""
    repo = {
        "app": [c("1.0", [d("a", ">=1.0")])],
        "a": [c("1.0", [d("b")]), c("2.0", [d("b")])],
        "b": [c("1.0", [d("a", "<2.0")])],
    }
    r = audit(repo, {"app": "1.0", "a": "2.0", "b": "1.0"})
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "constraint_mismatch",
            "package": "a",
            "locked_version": "2.0",
            "constraints": [
                {"from": "app==1.0", "specifier": ">=1.0"},
                {"from": "b==1.0", "specifier": "<2.0"},
            ],
        }
    ]


def test_audit_diamond_accumulates_constraints_from_all_parents():
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("core", ">=1.0,<2.0")])],
        "right": [c("1.0", [d("core", ">=1.5")])],
        "core": [c("1.0"), c("1.6"), c("2.0")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0", "core": "1.0"}
    r = audit(repo, lock)
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "constraint_mismatch",
            "package": "core",
            "locked_version": "1.0",
            "constraints": [
                {"from": "left==1.0", "specifier": ">=1.0,<2.0"},
                {"from": "right==1.0", "specifier": ">=1.5"},
            ],
        }
    ]


def test_audit_mismatch_still_expands_locked_version_dependencies():
    """锁定版本不满足约束时仍按其依赖继续遍历（完整诊断下游）。"""
    repo = {
        "app": [c("1.0", [d("a", ">=2.0")])],
        "a": [c("1.0", [d("b")]), c("2.0", [d("b")])],
        "b": [c("1.0")],
    }
    # a 锁 1.0（违反 >=2.0），其依赖 b 仍可达 -> b 不是 extraneous
    r = audit(repo, {"app": "1.0", "a": "1.0", "b": "1.0"})
    assert r.status_code == 200, r.text
    kinds = {i["package"]: i["kind"] for i in r.json()["issues"]}
    assert kinds == {"a": "constraint_mismatch"}


# --------------------------------------------------------------------- #
# 5. extraneous：锁中包不可达
# --------------------------------------------------------------------- #
def test_audit_extraneous_locked_package():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "ghost": "3.0"}
    r = audit(repo, lock)
    assert r.status_code == 200, r.text
    assert r.json()["issues"] == [
        {
            "kind": "extraneous",
            "package": "ghost",
            "locked_version": "3.0",
            "constraints": [],
        }
    ]


def test_audit_extraneous_for_snapshot_package_not_required():
    """包在快照中存在但不被任何已激活依赖需要 -> extraneous。"""
    repo = {
        "app": [c("1.0")],
        "libx": [c("1.0")],
    }
    r = audit(repo, {"app": "1.0", "libx": "1.0"})
    assert r.json()["issues"] == [
        {
            "kind": "extraneous",
            "package": "libx",
            "locked_version": "1.0",
            "constraints": [],
        }
    ]


# --------------------------------------------------------------------- #
# 6. PEP 503 规范化 与 marker 语义
# --------------------------------------------------------------------- #
def test_audit_lock_keys_and_repository_names_canonicalized():
    repo = {
        "App": [c("1.0", [d("Lib_X", ">=1.0")])],
        "lib-x": [c("1.0")],
    }
    r = audit(repo, {"APP": "1.0", "Lib.X": "1.0"}, root="app")
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}


def test_audit_inactive_marker_dependency_not_required():
    """未激活依赖不要求锁定；出现在锁中则记 extraneous。"""
    repo = {
        "app": [c("1.0", [
            d("win-only", marker="sys_platform == 'win32'"),
            d("real", "==1.0"),
        ])],
        "win-only": [c("1.0")],
        "real": [c("1.0")],
    }
    r = audit(repo, {"app": "1.0", "real": "1.0"})
    assert r.status_code == 200, r.text
    assert r.json() == {"valid": True, "issues": []}

    r2 = audit(repo, {"app": "1.0", "real": "1.0", "win-only": "1.0"})
    assert r2.json()["issues"] == [
        {
            "kind": "extraneous",
            "package": "win-only",
            "locked_version": "1.0",
            "constraints": [],
        }
    ]

    # 切到 win32 环境：win-only 变为必需，缺失即 missing
    win_env = {"python_version": "3.11", "sys_platform": "win32",
               "platform_machine": "AMD64"}
    r3 = audit(repo, {"app": "1.0", "real": "1.0"}, env=win_env)
    assert r3.json()["issues"] == [
        {
            "kind": "missing",
            "package": "win-only",
            "locked_version": None,
            "constraints": [{"from": "app==1.0", "specifier": "*"}],
        }
    ]


# --------------------------------------------------------------------- #
# 7. 预发布语义与 /resolve 一致
# --------------------------------------------------------------------- #
def test_audit_prerelease_follows_toggle():
    repo = {
        "app": [c("1.0", [d("libx", ">=1.0")])],
        "libx": [c("2.0rc1"), c("1.0")],
    }
    lock = {"app": "1.0", "libx": "2.0rc1"}
    r = audit(repo, lock)
    assert r.status_code == 200, r.text
    # 默认排除预发布：2.0rc1 不满足 >=1.0
    assert r.json()["issues"] == [
        {
            "kind": "constraint_mismatch",
            "package": "libx",
            "locked_version": "2.0rc1",
            "constraints": [{"from": "app==1.0", "specifier": ">=1.0"}],
        }
    ]

    r2 = audit(repo, lock, allow_prereleases=True)
    assert r2.json() == {"valid": True, "issues": []}


def test_audit_prerelease_pinned_explicitly_is_accepted():
    """约束显式钉住预发布（==2.0rc1）时，锁定该预发布有效。"""
    repo = {
        "app": [c("1.0", [d("libx", "==2.0rc1")])],
        "libx": [c("2.0rc1")],
    }
    r = audit(repo, {"app": "1.0", "libx": "2.0rc1"})
    assert r.json() == {"valid": True, "issues": []}


# --------------------------------------------------------------------- #
# 8. 确定性：排序与重复调用一致
# --------------------------------------------------------------------- #
def test_audit_issues_sorted_deterministically():
    repo = {
        "app": [c("1.0", [d("b-pkg"), d("a-pkg", ">=2.0")])],
        "a-pkg": [c("1.0"), c("2.0")],
        "b-pkg": [c("1.0")],
    }
    # a-pkg 锁 1.0（违反 >=2.0）；b-pkg 未锁；z-old 不可达
    lock = {"app": "1.0", "a-pkg": "1.0", "z-old": "0.1"}
    body1 = audit(repo, lock).json()
    body2 = audit(repo, lock).json()
    assert body1 == body2
    assert body1["valid"] is False
    assert [(i["package"], i["kind"]) for i in body1["issues"]] == [
        ("a-pkg", "constraint_mismatch"),
        ("b-pkg", "missing"),
        ("z-old", "extraneous"),
    ]


def test_audit_deterministic_regardless_of_input_order():
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0")],
        "liby": [c("1.0")],
    }
    lock = {"liby": "1.0", "app": "1.0", "libx": "1.0"}
    body1 = audit(repo, lock).json()
    # 反转 repository 与 current_lock 的键顺序，结果逐字节一致
    repo2 = dict(reversed(list(repo.items())))
    lock2 = dict(reversed(list(lock.items())))
    body2 = audit(repo2, lock2).json()
    assert body1 == body2


# --------------------------------------------------------------------- #
# 9. 422：快照 / current_lock / 请求非法
# --------------------------------------------------------------------- #
def test_audit_bad_snapshot_version_422():
    r = audit({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"
    assert "PEP 440" in r.json()["message"]


def test_audit_bad_lock_version_422():
    r = audit({"app": [c("1.0")]}, {"app": "not-a-version"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_audit_conflicting_lock_versions_422():
    # Lib_X 与 lib-x 规范化后同为 lib-x，但版本不同 -> 422
    r = audit({"app": [c("1.0")]}, {"Lib_X": "1.0", "lib-x": "2.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_audit_unknown_root_422():
    r = audit({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_audit_invalid_marker_422():
    repo = {"app": [c("1.0", [d("x", marker="os_name == 'posix'")])]}
    r = audit(repo, {"app": "1.0"})
    assert r.status_code == 422
    assert "os_name" in r.json()["message"]


def test_audit_missing_current_lock_422():
    body = {
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
    }
    r = client.post("/audit-lock", json=body)
    assert r.status_code == 422


def test_audit_extra_field_forbidden_422():
    r = audit({"app": [c("1.0")]}, {"app": "1.0"}, unknown_field=1)
    assert r.status_code == 422


def test_audit_bad_target_environment_422():
    env = dict(ENV, python_version="not-a-version")
    r = audit({"app": [c("1.0")]}, {"app": "1.0"}, env=env)
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# 10. 无共享状态：审计不影响 /resolve
# --------------------------------------------------------------------- #
def test_audit_does_not_change_resolve_behavior():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    resolve_body = {
        "repository": repo, "root": "app", "target_environment": ENV,
    }
    before = client.post("/resolve", json=resolve_body).json()
    audit(repo, {"app": "1.0", "libx": "1.0"})
    after = client.post("/resolve", json=resolve_body).json()
    assert before == after
