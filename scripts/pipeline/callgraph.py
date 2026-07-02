"""
callgraph.py - 함수 호출 관계 추출

레포 전체의 Python 파일을 파싱해서
"어떤 함수가 어떤 함수를 호출하는가"를 맵핑합니다.

이를 통해 소스(입력) → 싱크(위험 연산) 경로를 탐색할 수 있습니다.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FuncNode:
    """레포 내 함수 하나를 나타냅니다."""
    file_path: str
    name: str
    start_line: int
    end_line: int
    code: str


@dataclass
class CallGraph:
    """
    func_name → 호출하는 func_name 목록 (단순 이름 기반).
    전체 데이터플로우가 아닌 "같은 이름의 함수를 호출한다"는 근사입니다.
    """
    nodes: dict[str, FuncNode] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def callers_of(self, func_name: str) -> set[str]:
        """func_name을 호출하는 함수 목록."""
        return {caller for caller, callees in self.edges.items()
                if func_name in callees}

    def callees_of(self, func_name: str) -> set[str]:
        """func_name이 호출하는 함수 목록."""
        return self.edges.get(func_name, set())


def build_callgraph(repo_path: str | Path) -> CallGraph:
    """레포 전체를 파싱해서 콜 그래프를 빌드합니다."""
    repo = Path(repo_path)
    cg = CallGraph()

    _skip = {"tests", "test", ".git", "__pycache__", "node_modules",
              "venv", ".venv", "docs", "cookbook", "migrations"}

    all_files: list[tuple[Path, ast.Module, list[str]]] = []

    # 1단계: 전체 파일 파싱
    for fpath in repo.rglob("*.py"):
        if set(fpath.parts) & _skip:
            continue
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()
            tree = ast.parse(source)
            all_files.append((fpath, tree, lines))
        except SyntaxError:
            continue

    # 2단계: 함수 노드 등록
    for fpath, tree, lines in all_files:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                code = "\n".join(lines[start:end])
                func_node = FuncNode(
                    file_path=str(fpath),
                    name=node.name,
                    start_line=node.lineno,
                    end_line=end,
                    code=code,
                )
                # 동명 함수는 마지막 것으로 덮어씀 (단순화)
                cg.nodes[node.name] = func_node

    # 3단계: 호출 관계 추출
    for fpath, tree, lines in all_files:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            caller = node.name
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    # func() 형태
                    if isinstance(child.func, ast.Name):
                        cg.edges[caller].add(child.func.id)
                    # obj.method() 형태 — method 이름만
                    elif isinstance(child.func, ast.Attribute):
                        cg.edges[caller].add(child.func.attr)

    return cg
