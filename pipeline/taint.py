"""
소스→싱크 경로 추적 (경량 테인트 분석).

기존 chunker.py는 "소스가 있거나 위험 오퍼레이션이 있는 청크"를 따로 필터링했다.
이 모듈은 한 걸음 더 나아가:
  1. 외부 입력 소스(HTTP, JSON, 파일 파라미터)를 받는 청크를 찾고 (Source)
  2. 그 청크에서 시작해 콜 그래프를 BFS로 탐색해
  3. 위험 오퍼레이션(Sink)에 도달하는 경로를 찾는다.

결과: TaintPath 목록 — 각 경로는 "source→(중간 함수들)→sink"를 나타냄.
이 경로 전체를 하나의 청크로 묶어서 Haiku/Sonnet에 전달하면
"이 데이터가 어디서 오고 어디로 가는가"를 LLM이 한눈에 볼 수 있다.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .chunker import SemanticChunk, _SKIP, _SOURCES, _DANGERS, _py_files


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class TaintPath:
    """소스 함수에서 싱크 함수까지의 호출 경로."""
    source_chunk: SemanticChunk          # 외부 입력을 받는 함수
    sink_chunk:   SemanticChunk          # 위험 오퍼레이션이 있는 함수
    path_names:   list[str]              # 경로 상의 함수 이름들 (source → ... → sink)
    path_chunks:  list[SemanticChunk]    # 경로 상의 청크들

    def to_prompt(self, max_chars: int = 8000) -> str:
        """LLM에 전달할 통합 컨텍스트: 경로 전체 코드."""
        lines = [
            f"## TAINT PATH: `{self.source_chunk.name}` → `{self.sink_chunk.name}`",
            f"**경로:** {' → '.join(self.path_names)}",
            f"**외부 입력:** {', '.join(self.source_chunk.sources)}",
            f"**위험 오퍼레이션:** {', '.join(self.sink_chunk.dangers)}",
            "",
            "### 경로 상의 전체 코드:",
        ]
        total_chars = sum(len(l) for l in lines)

        for chunk in self.path_chunks:
            header = f"\n#### `{chunk.name}` ({chunk.file}:{chunk.line})\n```python\n"
            code   = chunk.code
            footer = "\n```"
            needed = len(header) + len(footer)

            if total_chars + needed + 200 > max_chars:
                break

            remaining = max_chars - total_chars - needed
            lines.append(header + code[:remaining] + footer)
            total_chars += len(header) + min(len(code), remaining) + len(footer)

        return "\n".join(lines)


# ── 크로스파일 콜 그래프 ──────────────────────────────────────────────────────

@dataclass
class CallGraph:
    """파일 간 콜 그래프. 각 노드는 (file, func_name) 쌍."""
    nodes:   dict[str, SemanticChunk]   # "file::func" → chunk
    edges:   dict[str, set[str]]        # caller_id → set(callee_id)
    r_edges: dict[str, set[str]]        # callee_id → set(caller_id)

    @staticmethod
    def _id(chunk: SemanticChunk) -> str:
        return f"{chunk.file}::{chunk.name}"


def build_call_graph(chunks: list[SemanticChunk]) -> CallGraph:
    """
    청크 목록에서 크로스파일 콜 그래프를 구성.
    같은 이름의 함수가 여러 파일에 있으면 모두 callee 후보로 등록.
    """
    # 함수 이름 → 청크 목록 (같은 이름이 여러 파일에 있을 수 있음)
    name_to_chunks: dict[str, list[SemanticChunk]] = {}
    for c in chunks:
        short = c.name.split(".")[-1]   # ClassName.method → method
        name_to_chunks.setdefault(short, []).append(c)

    nodes:   dict[str, SemanticChunk] = {CallGraph._id(c): c for c in chunks}
    edges:   dict[str, set[str]]       = {CallGraph._id(c): set() for c in chunks}
    r_edges: dict[str, set[str]]       = {CallGraph._id(c): set() for c in chunks}

    for caller in chunks:
        caller_id = CallGraph._id(caller)
        # 이 함수의 코드에서 다른 함수 이름이 호출 형태로 등장하면 edge 추가
        for fname, callee_list in name_to_chunks.items():
            if not re.search(rf"\b{re.escape(fname)}\s*\(", caller.code):
                continue
            for callee in callee_list:
                if callee is caller:
                    continue
                callee_id = CallGraph._id(callee)
                edges[caller_id].add(callee_id)
                r_edges[callee_id].add(caller_id)

    return CallGraph(nodes=nodes, edges=edges, r_edges=r_edges)


# ── 소스→싱크 경로 탐색 ───────────────────────────────────────────────────────

def find_taint_paths(
    graph: CallGraph,
    chunks: list[SemanticChunk],
    max_depth: int = 5,
) -> list[TaintPath]:
    """
    소스 청크에서 BFS로 싱크 청크까지 도달하는 경로를 탐색.
    max_depth 단계 이내에서 찾는다.
    """
    sources = [c for c in chunks if c.sources]
    sinks   = {CallGraph._id(c): c for c in chunks if c.dangers}

    taint_paths: list[TaintPath] = []
    seen_pairs: set[tuple[str, str]] = set()

    for source in sources:
        source_id = CallGraph._id(source)
        # BFS: (현재_id, 경로)
        queue: deque[tuple[str, list[str]]] = deque([(source_id, [source_id])])
        visited: set[str] = {source_id}

        while queue:
            curr_id, path = queue.popleft()
            if len(path) > max_depth:
                continue

            if curr_id in sinks and curr_id != source_id:
                pair = (source_id, curr_id)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    path_chunks = [graph.nodes[nid] for nid in path if nid in graph.nodes]
                    taint_paths.append(TaintPath(
                        source_chunk=source,
                        sink_chunk=sinks[curr_id],
                        path_names=[graph.nodes[nid].name for nid in path if nid in graph.nodes],
                        path_chunks=path_chunks,
                    ))

            for callee_id in graph.edges.get(curr_id, set()):
                if callee_id not in visited:
                    visited.add(callee_id)
                    queue.append((callee_id, path + [callee_id]))

    # 경로 중복 제거 (더 짧은 경로 우선)
    taint_paths.sort(key=lambda p: len(p.path_names))
    return taint_paths


# ── 공개 인터페이스 ───────────────────────────────────────────────────────────

def analyze_repo(repo_dir: Path, max_depth: int = 5) -> list[TaintPath]:
    """레포 전체를 분석해 소스→싱크 테인트 경로 목록 반환."""
    from .chunker import build_chunks
    chunks = build_chunks(repo_dir)
    graph  = build_call_graph(chunks)
    paths  = find_taint_paths(graph, chunks, max_depth=max_depth)
    return paths
