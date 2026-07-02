"""
differential.py — Stage 1.5: 불일치(asymmetry) 탐지

미지의 취약점을 찾는 핵심 엔진.

원리:
  같은 민감 연산(sink)에 도달하는 여러 경로 중,
  일부 경로엔 보호장치(guard)가 있는데 다른 경로엔 없다면 —
  그 보호 없는 경로가 취약점 후보다.

  "기대되는 보호장치"를 gates.yaml에 하드코딩하지 않고
  코드베이스 자신(형제 경로)으로부터 학습한다.

  → 취약점 종류를 몰라도 권한 우회/검증 누락을 발견 가능.
  → datasette ?_facet= 케이스가 정확히 이 패턴.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

MAX_DEPTH = 10

# 보호장치로 추정되는 함수 이름 패턴 (gates.yaml 보강 — 이름 기반 추론)
_GUARD_REGEX = re.compile(
    r"(check|validate|verify|ensure|assert|sanitiz|escap|allow|"
    r"authori[sz]|authenticat|permission|forbid|require|guard|"
    r"is_valid|is_safe|is_allowed|can_|has_perm|clean|filter|"
    r"_validate|reject|deny|restrict)",
    re.IGNORECASE,
)


@dataclass
class DiffCandidate:
    """불일치 후보 — 형제 경로엔 있는 보호장치가 이 경로엔 없음."""
    sink_name: str
    sink_kind: str
    sink_file: str
    sink_line: int
    sink_code: str

    entry_name: str
    entry_file: str
    entry_code: str
    path: list[str]

    guards_on_this_path: list[str]      # 이 경로의 보호장치
    guards_on_sibling_paths: list[str]  # 형제 경로들의 보호장치
    missing_guards: list[str]           # 형제엔 있는데 여기 없는 것 (핵심 시그널)
    sibling_entry: str                  # 보호장치를 가진 형제 진입점 (비교 대상)

    def asymmetry_score(self) -> float:
        """불일치 강도. 형제는 보호하는데 나는 안 하는 정도."""
        if not self.guards_on_sibling_paths:
            return 0.0
        return len(self.missing_guards) / max(len(self.guards_on_sibling_paths), 1)


def _load_graph(db_path: Path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    nodes = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM nodes")}
    name_to_id = {}
    for nid, n in nodes.items():
        name_to_id.setdefault(n["name"], nid)
    edges: dict[int, set[str]] = defaultdict(set)
    for r in conn.execute("SELECT caller_id, callee_name FROM edges"):
        edges[r["caller_id"]].add(r["callee_name"])
    conn.close()
    return nodes, name_to_id, edges


def _is_guard_call(callee_name: str, gate_names: set[str]) -> bool:
    """이 호출이 보호장치인가? (명시 게이트 + 이름 패턴 추론)"""
    if callee_name in gate_names:
        return True
    return bool(_GUARD_REGEX.search(callee_name))


def _guards_on_path(
    path_ids: list[int],
    edges: dict[int, set[str]],
    gate_names: set[str],
) -> set[str]:
    """
    경로상의 모든 함수가 호출하는 보호장치 집합.
    경로 = entry부터 sink 직전까지 (sink 자체는 제외).
    """
    guards = set()
    for nid in path_ids:
        for callee in edges.get(nid, set()):
            if _is_guard_call(callee, gate_names):
                guards.add(callee)
    return guards


def find_differential_candidates(
    db_path: str | Path,
    gate_names: set[str] | None = None,
    min_siblings: int = 2,
) -> list[DiffCandidate]:
    """
    모든 싱크에 대해:
      1. 그 싱크에 도달하는 모든 entry→sink 경로 수집
      2. 각 경로의 보호장치 집합 계산
      3. 형제 경로엔 있는데 이 경로엔 없는 보호장치 탐지
    """
    db_path = Path(db_path)
    nodes, name_to_id, edges = _load_graph(db_path)

    if gate_names is None:
        gate_names = {n["name"] for n in nodes.values() if n["is_gate"]}

    entries = [n for n in nodes.values() if n["is_entry"]]
    sink_names = {n["name"] for n in nodes.values() if n["is_sink"]}

    # sink_name → list of (entry_node, path_ids, path_names, guards)
    paths_to_sink: dict[str, list[dict]] = defaultdict(list)

    for entry in entries:
        start_id = entry["id"]
        # BFS, 경로의 node id 시퀀스를 추적
        queue: deque[tuple[int, list[int], list[str]]] = deque()
        queue.append((start_id, [start_id], [entry["name"]]))
        visited_on_path = set()

        while queue:
            cur_id, path_ids, path_names = queue.popleft()
            if len(path_ids) > MAX_DEPTH:
                continue

            for callee in edges.get(cur_id, set()):
                if callee in sink_names:
                    # 경로 발견: entry → ... → sink
                    guards = _guards_on_path(path_ids, edges, gate_names)
                    paths_to_sink[callee].append({
                        "entry": entry,
                        "path_ids": path_ids,
                        "path_names": path_names + [callee],
                        "guards": guards,
                    })

                callee_id = name_to_id.get(callee)
                if callee_id and callee not in path_names:
                    queue.append((callee_id, path_ids + [callee_id],
                                  path_names + [callee]))

    # 불일치 분석: 같은 sink로 가는 경로들 비교
    candidates: list[DiffCandidate] = []

    for sink_name, paths in paths_to_sink.items():
        if len(paths) < min_siblings:
            continue  # 비교 대상이 없으면 불일치 판단 불가

        sink_id = name_to_id.get(sink_name)
        sink_node = nodes.get(sink_id, {})

        # 모든 형제 경로의 보호장치 합집합
        all_guards = set()
        for p in paths:
            all_guards |= p["guards"]

        if not all_guards:
            continue  # 아무도 보호 안 하면 불일치 아님 (전부 위험 or 전부 안전)

        for p in paths:
            missing = all_guards - p["guards"]
            if not missing:
                continue  # 이 경로는 모든 보호장치를 가짐 → 안전

            # 누락 보호장치를 가진 형제 찾기 (비교 근거)
            sibling = next(
                (q for q in paths if q is not p and (q["guards"] & missing)),
                None,
            )
            sibling_entry = sibling["entry"]["name"] if sibling else "?"

            entry = p["entry"]
            candidates.append(DiffCandidate(
                sink_name=sink_name,
                sink_kind=sink_node.get("sink_kind", ""),
                sink_file=sink_node.get("file", ""),
                sink_line=sink_node.get("start_line", 0),
                sink_code=sink_node.get("code", ""),
                entry_name=entry["name"],
                entry_file=entry["file"],
                entry_code=entry["code"],
                path=p["path_names"],
                guards_on_this_path=sorted(p["guards"]),
                guards_on_sibling_paths=sorted(all_guards),
                missing_guards=sorted(missing),
                sibling_entry=sibling_entry,
            ))

    # 불일치 강도 순 정렬
    candidates.sort(key=lambda c: c.asymmetry_score(), reverse=True)
    return candidates


def run_differential(
    db_path: str | Path,
    out_path: str | Path | None = None,
) -> Path:
    db_path = Path(db_path)
    if out_path is None:
        out_path = db_path.parent / "differential.jsonl"
    out_path = Path(out_path)

    candidates = find_differential_candidates(db_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps({
                "sink_name": c.sink_name,
                "sink_kind": c.sink_kind,
                "sink_file": c.sink_file,
                "sink_line": c.sink_line,
                "sink_code": c.sink_code,
                "entry_name": c.entry_name,
                "entry_file": c.entry_file,
                "entry_code": c.entry_code,
                "path": c.path,
                "guards_on_this_path": c.guards_on_this_path,
                "guards_on_sibling_paths": c.guards_on_sibling_paths,
                "missing_guards": c.missing_guards,
                "sibling_entry": c.sibling_entry,
                "asymmetry_score": round(c.asymmetry_score(), 3),
            }, ensure_ascii=False) + "\n")

    print(f"  불일치 후보: {len(candidates)}개")
    for c in candidates[:5]:
        print(f"    [{c.asymmetry_score():.2f}] {c.entry_name} -> {c.sink_name} "
              f"| 누락 보호: {c.missing_guards} (형제 {c.sibling_entry}엔 있음)")

    return out_path
