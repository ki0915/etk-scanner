"""
static_filter.py — Stage 1: 정적 필터 (LLM 0)

graph.db에서 아래 조건을 모두 만족하는 후보를 추출한다:
  1. 진입점(entry)에서 호출 그래프상 도달 가능
  2. 위험 싱크(sink)를 포함
  3. 테스트/목/픽스처 코드 아님

출력: candidates.jsonl
  {"chunk_id": int, "entry_name": str, "entry_file": str,
   "sink_name": str, "sink_kind": str, "path": [str], "code": str}
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from pathlib import Path

MAX_DEPTH = 8
_TEST_KEYWORDS = ("test_", "_test", "mock_", "_mock", "fixture", "conftest", "fake_")


def _is_test_file(filepath: str) -> bool:
    p = filepath.lower()
    return any(k in p for k in ("/test", "/tests", "test_", "_test", "conftest", "mock"))


def _is_test_func(name: str) -> bool:
    n = name.lower()
    return any(n.startswith(k) or n.endswith(k.rstrip("_")) for k in _TEST_KEYWORDS)


def run_static_filter(
    db_path: str | Path,
    out_path: str | Path | None = None,
    max_candidates: int | None = None,
) -> Path:
    db_path = Path(db_path)
    if out_path is None:
        out_path = db_path.parent / "candidates.jsonl"
    out_path = Path(out_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # 모든 노드 로드
    nodes = {row["id"]: dict(row) for row in conn.execute("SELECT * FROM nodes")}
    # 이름 → id 맵 (동명 함수는 마지막 것)
    name_to_id: dict[str, int] = {}
    for nid, node in nodes.items():
        name_to_id[node["name"]] = nid

    # 엣지: caller_id → set of callee_name
    edges: dict[int, set[str]] = {}
    for row in conn.execute("SELECT caller_id, callee_name FROM edges"):
        edges.setdefault(row["caller_id"], set()).add(row["callee_name"])

    conn.close()

    # 진입점 목록
    entries = [n for n in nodes.values() if n["is_entry"] and
               not _is_test_file(n["file"]) and not _is_test_func(n["name"])]

    # 싱크 이름 집합
    sink_names = {n["name"] for n in nodes.values() if n["is_sink"]}

    candidates = []
    seen_pairs: set[tuple[int, str]] = set()

    for entry in entries:
        start_id = entry["id"]
        # BFS: (node_id, path)
        queue: deque[tuple[int, list[str]]] = deque()
        queue.append((start_id, [entry["name"]]))

        while queue:
            cur_id, path = queue.popleft()
            if len(path) > MAX_DEPTH:
                continue

            for callee_name in edges.get(cur_id, set()):
                new_path = path + [callee_name]

                if callee_name in sink_names:
                    pair = (start_id, callee_name)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)

                    callee_id = name_to_id.get(callee_name)
                    if callee_id is None:
                        continue
                    sink_node = nodes[callee_id]

                    candidates.append({
                        "chunk_id": callee_id,
                        "entry_name": entry["name"],
                        "entry_file": entry["file"],
                        "sink_name": callee_name,
                        "sink_kind": sink_node["sink_kind"],
                        "sink_file": sink_node["file"],
                        "sink_line": sink_node["start_line"],
                        "path": new_path,
                        "code": sink_node["code"],
                        "entry_code": entry["code"],
                    })

                elif callee_name not in path:
                    callee_id = name_to_id.get(callee_name)
                    if callee_id:
                        queue.append((callee_id, new_path))

    # 상한 적용 (sink_kind 다양성 우선)
    if max_candidates and len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"  진입점: {len(entries)} | 후보: {len(candidates)}")
    return out_path
