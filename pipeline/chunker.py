"""
의미 단위 청크 분할기 (Python 특화).

함수/메서드를 단위로 분리하되, 각 청크에:
  - 클래스 컨텍스트 (메서드라면 클래스 선언 포함)
  - 핵심 import
  - 파일 내 콜 그래프 (호출자 ↔ 피호출자)
  - 외부 입력 소스 / 위험 오퍼레이션 힌트

를 붙여 LLM이 데이터 흐름을 추론할 수 있도록 한다.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


# ── 패턴 ─────────────────────────────────────────────────────────────────────

_SOURCES = [
    r"request\.(args|form|json|data|files|values|cookies|headers)\b",
    r"json\.loads?\s*\(",
    r"yaml\.(?:safe_)?load\s*\(",
    r"os\.environ(?:\.get)?\b",
    r"sys\.argv\b",
    r"\bstdin\b",
    # multipart / HTTP 파서 전용
    r"\bdata\b", r"\bbody\b", r"\bcontent\b", r"\bstream\b",
]

_DANGERS = [
    r"\beval\s*\(",  r"\bexec\s*\(",  r"\bcompile\s*\(",
    r"pickle\.loads?\b",  r"yaml\.load\b",  r"marshal\.loads\b",
    r"subprocess\.", r"os\.system\b", r"os\.popen\b",
    r"\.execute\s*\(",  r"\.executemany\s*\(",
    r"\bopen\s*\(",  r"os\.path\.join\b",
    r"requests?\.(get|post)\s*\(",  r"httpx\.(get|post)\b",
    # 정규식 복잡도 (ReDoS)
    r"re\.compile\b",  r"re\.match\b",  r"re\.search\b",
]

_SKIP = {".git", "__pycache__", "node_modules", "dist", "build",
         "test", "tests", "spec", ".venv", "venv", "vendor", "migrations",
         "fuzz", "scripts", "docs", "examples", "benchmark", "benchmarks"}


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class SemanticChunk:
    file: str           # 레포 기준 상대 경로
    name: str           # 함수명 (클래스 메서드면 ClassName.method_name)
    line: int
    code: str           # 함수 본문
    class_ctx: str      # 클래스 선언 + 속성 (메서드일 때만)
    imports: str        # 파일 최상단 import 요약
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    dangers: list[str] = field(default_factory=list)

    @property
    def interesting(self) -> bool:
        return bool(self.sources) or bool(self.dangers)

    def to_prompt(self, max_code: int = 3000) -> str:
        parts = [f"### [{self.file}:{self.line}] `{self.name}`"]
        if self.imports:
            parts.append(f"**imports:** {self.imports}")
        if self.class_ctx:
            parts.append(f"**class context:**\n```python\n{self.class_ctx[:600]}\n```")
        if self.callers:
            parts.append(f"**호출자:** {', '.join(self.callers[:5])}")
        if self.callees:
            parts.append(f"**호출 대상:** {', '.join(self.callees[:5])}")
        if self.sources:
            parts.append(f"**감지된 입력 소스:** {', '.join(self.sources)}")
        if self.dangers:
            parts.append(f"**감지된 위험 오퍼레이션:** {', '.join(self.dangers)}")
        parts.append(f"```python\n{self.code[:max_code]}\n```")
        return "\n".join(parts)


# ── 공개 API ──────────────────────────────────────────────────────────────────

def build_chunks(repo_dir: Path) -> list[SemanticChunk]:
    all_chunks: list[SemanticChunk] = []
    for path in _py_files(repo_dir):
        source = path.read_text(encoding="utf-8", errors="ignore")
        rel    = str(path.relative_to(repo_dir))
        chunks = _parse(source, rel)
        _annotate_callgraph(chunks)
        _annotate_signals(chunks)
        all_chunks.extend(chunks)
    return all_chunks


def interesting_chunks(chunks: list[SemanticChunk]) -> list[SemanticChunk]:
    return [c for c in chunks if c.interesting]


# ── 파싱 ──────────────────────────────────────────────────────────────────────

def _parse(source: str, rel: str) -> list[SemanticChunk]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines   = source.splitlines()
    imports = _extract_imports(tree)
    chunks: list[SemanticChunk] = []

    for node in ast.walk(tree):
        # 클래스 메서드
        if isinstance(node, ast.ClassDef):
            class_ctx = _class_header(lines, node)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    chunks.append(_make_chunk(
                        lines, rel, item, imports,
                        class_ctx=class_ctx,
                        name=f"{node.name}.{item.name}",
                    ))
        # 모듈 레벨 함수
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 클래스 안에 있는 것은 위에서 처리
            if not _is_inside_class(tree, node):
                chunks.append(_make_chunk(lines, rel, node, imports))

    return chunks


def _make_chunk(
    lines: list[str],
    rel: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: str,
    class_ctx: str = "",
    name: str = "",
) -> SemanticChunk:
    start = node.lineno - 1
    end   = (node.end_lineno or start + 60)
    code  = "\n".join(lines[start:end])
    return SemanticChunk(
        file=rel,
        name=name or node.name,
        line=node.lineno,
        code=code,
        class_ctx=class_ctx,
        imports=imports,
    )


def _class_header(lines: list[str], node: ast.ClassDef) -> str:
    """클래스 선언 + 클래스 변수 (최대 20줄)."""
    start = node.lineno - 1
    snippet = "\n".join(lines[start : start + 20])
    return snippet


def _extract_imports(tree: ast.Module) -> str:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.append(a.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return ", ".join(sorted(set(names))[:12])


def _is_inside_class(tree: ast.Module, func: ast.FunctionDef) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in ast.walk(node):
                if item is func:
                    return True
    return False


# ── 콜 그래프 ─────────────────────────────────────────────────────────────────

def _annotate_callgraph(chunks: list[SemanticChunk]) -> None:
    name_map = {c.name.split(".")[-1]: c for c in chunks}

    for chunk in chunks:
        for fname, other in name_map.items():
            if other is chunk:
                continue
            if re.search(rf"\b{re.escape(fname)}\s*\(", chunk.code):
                short = other.name
                if short not in chunk.callees:
                    chunk.callees.append(short)
                if chunk.name not in other.callers:
                    other.callers.append(chunk.name)


# ── 소스 / 위험 어노테이션 ───────────────────────────────────────────────────

def _annotate_signals(chunks: list[SemanticChunk]) -> None:
    for chunk in chunks:
        for pat in _SOURCES:
            m = re.search(pat, chunk.code)
            if m:
                chunk.sources.append(m.group(0)[:40])
        for pat in _DANGERS:
            m = re.search(pat, chunk.code)
            if m:
                chunk.dangers.append(m.group(0)[:40])


# ── 파일 순회 ─────────────────────────────────────────────────────────────────

def _py_files(repo_dir: Path):
    for path in repo_dir.rglob("*.py"):
        if any(p in _SKIP for p in path.parts):
            continue
        if path.stat().st_size > 300_000:
            continue
        yield path
