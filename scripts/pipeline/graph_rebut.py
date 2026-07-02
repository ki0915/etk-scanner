"""
graph_rebut.py — Stage 3: 그래프 반증 (LLM 0)

가설의 required_gate가 진입점→싱크 경로에 존재하면 기각.
게이트가 없는 가설만 survivors.jsonl로 통과.

이것이 Sonnet/Opus 호출을 80~90% 줄이는 핵심 단계다.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _save_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _get_gate_names(db_path: Path) -> set[str]:
    """graph.db에서 is_gate=1인 함수 이름 목록."""
    conn = sqlite3.connect(db_path)
    gates = {row[0] for row in conn.execute(
        "SELECT name FROM nodes WHERE is_gate=1"
    )}
    conn.close()
    return gates


def _path_has_gate(path: list[str], gate_names: set[str]) -> tuple[bool, str]:
    """경로 중 게이트가 있으면 (True, gate_name) 반환."""
    for func in path:
        if func in gate_names:
            return True, func
    return False, ""


def run_graph_rebut(
    hypotheses_path: str | Path,
    db_path: str | Path,
    survivors_path: str | Path | None = None,
    rejected_path: str | Path | None = None,
) -> Path:
    hypotheses_path = Path(hypotheses_path)
    db_path = Path(db_path)

    data_dir = db_path.parent
    if survivors_path is None:
        survivors_path = data_dir / "survivors.jsonl"
    if rejected_path is None:
        rejected_path = data_dir / "rejected_by_graph.jsonl"

    survivors_path = Path(survivors_path)
    rejected_path = Path(rejected_path)

    hypotheses = _load_jsonl(hypotheses_path)
    gate_names = _get_gate_names(db_path)

    survivors = []
    rejected = []

    for hyp in hypotheses:
        # 후보 경로 (candidates.jsonl의 path 필드)
        path = hyp.get("path", [])
        # 가설의 required_gate (Haiku가 생성)
        required_gate = hyp.get("required_gate", "")

        # 1. 그래프 DB 게이트 이름으로 체크
        has_gate, gate_found = _path_has_gate(path, gate_names)

        # 2. required_gate 이름이 경로에 명시적으로 있는지 체크
        if not has_gate and required_gate:
            gate_parts = set(required_gate.split("."))
            has_gate = bool(gate_parts & set(path))
            if has_gate:
                gate_found = required_gate

        if has_gate:
            rejected.append({**hyp, "rejected_reason": f"gate_on_path: {gate_found}"})
        else:
            survivors.append(hyp)

    _save_jsonl(survivors_path, survivors)
    _save_jsonl(rejected_path, rejected)

    print(f"  가설: {len(hypotheses)} | 생존: {len(survivors)} | 기각: {len(rejected)}")
    return survivors_path
