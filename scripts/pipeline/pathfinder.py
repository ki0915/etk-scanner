"""
pathfinder.py - 소스 → 싱크 경로 탐색

콜 그래프를 BFS로 탐색해서
"외부 입력점(소스)에서 위험 연산(싱크)까지 닿는 경로"를 찾습니다.

이 경로가 있을 때만 Haiku에 스크리닝을 요청합니다.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from pipeline.callgraph import CallGraph
from pipeline.surface import Sink, Source


MAX_DEPTH = 8   # 탐색 최대 깊이 (너무 깊으면 노이즈)


@dataclass
class VulnPath:
    """
    소스에서 싱크까지 연결된 경로.
    Haiku 스크리너에 전달되는 핵심 컨텍스트입니다.
    """
    source: Source
    sink: Sink
    path: list[str]          # 함수 호출 체인: [source_func, ..., sink_func]
    path_code: list[str]     # 각 함수의 실제 코드

    @property
    def depth(self) -> int:
        return len(self.path)

    def to_prompt_block(self) -> str:
        """Haiku에게 보낼 컨텍스트 블록."""
        lines = [
            f"## Vulnerability Path Analysis",
            f"",
            f"**Source:** `{self.source.func_name}` ({self.source.file_path}:{self.source.line})",
            f"  - External input: `{self.source.detail}` (type: {self.source.kind})",
            f"",
            f"**Sink:** `{self.sink.func_name}` ({self.sink.file_path}:{self.sink.line})",
            f"  - Dangerous operation: `{self.sink.detail}` (type: {self.sink.kind})",
            f"",
            f"**Call chain:** {' → '.join(self.path)}",
            f"",
            f"## Code along the path",
            f"",
        ]
        for func_name, code in zip(self.path, self.path_code):
            lines.append(f"### `{func_name}`")
            lines.append(f"```python")
            lines.append(code)
            lines.append(f"```")
            lines.append("")

        return "\n".join(lines)


def find_paths(
    sources: list[Source],
    sinks: list[Sink],
    cg: CallGraph,
    max_depth: int = MAX_DEPTH,
) -> list[VulnPath]:
    """
    소스 함수에서 BFS로 max_depth 깊이까지 탐색해
    싱크 함수에 닿는 경로를 모두 반환합니다.
    """
    sink_func_names = {s.func_name for s in sinks}
    sink_by_name = {s.func_name: s for s in sinks}

    paths: list[VulnPath] = []
    seen_pairs: set[tuple[str, str]] = set()  # 중복 경로 방지

    for source in sources:
        start = source.func_name
        if start not in cg.nodes:
            continue

        # BFS: (현재 함수, 경로)
        queue: deque[tuple[str, list[str]]] = deque()
        queue.append((start, [start]))

        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            for callee in cg.callees_of(current):
                new_path = path + [callee]

                if callee in sink_func_names:
                    pair = (source.func_name, callee)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)

                    sink = sink_by_name[callee]

                    # 경로상 함수들의 코드 수집
                    path_code = []
                    for fname in new_path:
                        if fname in cg.nodes:
                            path_code.append(cg.nodes[fname].code)
                        else:
                            path_code.append(f"# {fname}: source not found")

                    paths.append(VulnPath(
                        source=source,
                        sink=sink,
                        path=new_path,
                        path_code=path_code,
                    ))
                elif callee not in path:  # 순환 방지
                    queue.append((callee, new_path))

    return paths


def deduplicate_paths(paths: list[VulnPath]) -> list[VulnPath]:
    """
    같은 소스 종류 + 싱크 종류 조합은 대표 하나만 남깁니다.
    경로가 짧을수록 우선합니다.
    """
    best: dict[tuple[str, str], VulnPath] = {}
    for p in sorted(paths, key=lambda x: x.depth):
        key = (p.source.kind, p.sink.kind)
        if key not in best:
            best[key] = p
    return list(best.values())
