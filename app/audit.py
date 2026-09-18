"""POST /audit-lock 的锁定清单审计器。

只审计、不重新求解：以 ``current_lock`` 的锁定版本为事实，从根包出发沿
**已激活**依赖（marker 已在构建仓库快照时按请求环境过滤）遍历可达图。
环上的包只展开一次，但其所有入边约束仍会累计，并在遍历结束后统一校验
（因此环/菱形路径后到的约束也不会漏判）。

判定规则（按包归类，每包至多一条 issue）：

* ``missing``：可达的包未出现在锁定清单中（无法展开其依赖）；
* ``unavailable``：锁定版本不在快照中（按 PEP 440 等价性匹配，如
  ``1.0`` 与 ``1.0.0`` 视为同一版本；版本未知故同样无法展开其依赖）；
* ``constraint_mismatch``：锁定版本不满足根约束或任一入边依赖约束
  （预发布语义与求解器一致，见 ``version_satisfies``）；
* ``extraneous``：锁定清单中的包从根不可达。

包名一律按 PEP 503 规范化（由 repository 层完成）；输出按
``(package, kind)`` 排序，约束按 ``(from, specifier)`` 排序，结果与输入
字典顺序无关。
"""

from __future__ import annotations

from collections import deque

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .repository import Candidate, Repository
from .resolver import version_satisfies

# 根请求在约束来源中的虚拟声明方（与 resolver 依赖边的 "root" 一致）。
_ROOT = "root"


def _find_candidate(
    repo: Repository, name: str, locked: Version
) -> Candidate | None:
    """快照中与锁定版本 PEP 440 等价的候选；不存在则为 None。"""
    for cand in repo.candidates(name):
        if cand.version == locked:
            return cand
    return None


def find_lock_issues(
    repo: Repository,
    root: str,
    root_spec: SpecifierSet,
    root_raw: str,
    current_lock: dict[str, Version],
    *,
    allow_prereleases: bool = False,
) -> list[dict]:
    """审计 current_lock，返回确定性排序的 issues 列表（空列表即有效）。

    ``root`` 与 ``current_lock`` 的键均须已按 PEP 503 规范化（由
    repository 层的 canonical / parse_current_lock 保证）。
    """
    # subject -> {(来源, 原始约束文本): SpecifierSet}，累计全部入边约束。
    incoming: dict[str, dict[tuple[str, str], SpecifierSet]] = {
        root: {(_ROOT, root_raw.strip() or "*"): root_spec}
    }
    expanded: set[str] = set()
    queue: deque[str] = deque([root])

    # --- 第一遍：遍历可达图，累计约束；每个包只展开一次（环安全） --------
    while queue:
        pkg = queue.popleft()
        if pkg in expanded:
            continue
        expanded.add(pkg)

        locked = current_lock.get(pkg)
        if locked is None:
            continue  # missing：无锁定版本，依赖未知，无法展开
        candidate = _find_candidate(repo, pkg, locked)
        if candidate is None:
            continue  # unavailable：锁定版本不在快照，依赖未知，无法展开

        origin = f"{pkg}=={candidate.version}"
        for dep in candidate.deps:
            bucket = incoming.setdefault(dep.name, {})
            bucket.setdefault((origin, dep.raw_spec), dep.spec)
            if dep.name not in expanded:
                queue.append(dep.name)

    # --- 第二遍：全部入边约束已累计完毕，逐包判定 ------------------------
    issues: list[dict] = []
    for pkg, entries in incoming.items():
        constraints = [
            {"from": source, "specifier": raw}
            for (source, raw) in sorted(entries)
        ]
        locked = current_lock.get(pkg)
        if locked is None:
            issues.append(
                {
                    "kind": "missing",
                    "package": pkg,
                    "locked_version": None,
                    "constraints": constraints,
                }
            )
            continue
        if _find_candidate(repo, pkg, locked) is None:
            issues.append(
                {
                    "kind": "unavailable",
                    "package": pkg,
                    "locked_version": str(locked),
                    "constraints": constraints,
                }
            )
            continue
        if not all(
            version_satisfies(locked, spec, allow_prereleases)
            for spec in entries.values()
        ):
            issues.append(
                {
                    "kind": "constraint_mismatch",
                    "package": pkg,
                    "locked_version": str(locked),
                    "constraints": constraints,
                }
            )

    # 锁定清单中不可达的包。
    for pkg, locked in current_lock.items():
        if pkg not in incoming:
            issues.append(
                {
                    "kind": "extraneous",
                    "package": pkg,
                    "locked_version": str(locked),
                    "constraints": [],
                }
            )

    issues.sort(key=lambda issue: (issue["package"], issue["kind"]))
    return issues
