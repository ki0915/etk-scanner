"""
Call chain 컨텍스트 수집기.
싱크 파일에서 import 관계를 따라가 실제 attack path에 관련된
코드를 수집해 Sonnet에 전달할 단일 컨텍스트를 만든다.
"""

import ast
import re
from pathlib import Path


def collect_context(
    repo_dir: Path,
    sink_file: str,
    sink_line: int | None,
    max_tokens: int = 35_000,
) -> str:
    """
    싱크 파일을 중심으로 import 그래프를 1-hop 탐색해
    관련 파일들을 모아 하나의 컨텍스트 문자열로 반환.
    """
    sink_path = _resolve(repo_dir, sink_file)
    if not sink_path:
        return ""

    parts: list[str] = []
    seen: set[Path] = set()

    # 1. 싱크 파일 전체 (핵심)
    content = sink_path.read_text(encoding="utf-8", errors="ignore")
    parts.append(_format_file(sink_path, repo_dir, content, sink_line))
    seen.add(sink_path)
    budget = max_tokens - len(content)

    # 2. 싱크 파일에서 import하는 로컬 모듈 (1-hop)
    local_imports = _extract_local_imports(content, sink_path, repo_dir)
    for imp_path in local_imports:
        if imp_path in seen or budget < 500:
            break
        imp_content = imp_path.read_text(encoding="utf-8", errors="ignore")
        parts.append(_format_file(imp_path, repo_dir, imp_content[:8000]))
        seen.add(imp_path)
        budget -= len(imp_content[:8000])

    # 3. 싱크 파일을 import하는 파일들 (역방향 — 라우터/엔트리포인트)
    callers = _find_callers(repo_dir, sink_path, seen)
    for caller_path in callers[:3]:
        if budget < 500:
            break
        caller_content = caller_path.read_text(encoding="utf-8", errors="ignore")
        parts.append(_format_file(caller_path, repo_dir, caller_content[:8000]))
        seen.add(caller_path)
        budget -= len(caller_content[:8000])

    separator = "\n\n" + "=" * 60 + "\n\n"
    result = separator.join(parts)
    return result[:max_tokens * 4]  # 문자 기준 (토큰 ≈ 4자)


def _resolve(repo_dir: Path, file_path: str) -> Path | None:
    """파일 경로를 절대 경로로 변환. 없으면 이름으로 검색."""
    target = repo_dir / file_path.lstrip("/\\")
    if target.exists():
        return target
    name = Path(file_path).name
    for p in repo_dir.rglob(name):
        if ".git" not in str(p) and "node_modules" not in str(p):
            return p
    return None


def _format_file(path: Path, repo_dir: Path, content: str, highlight_line: int | None = None) -> str:
    try:
        rel = str(path.relative_to(repo_dir))
    except ValueError:
        rel = path.name
    header = f"# FILE: {rel}"
    if highlight_line:
        header += f"  ← SINK AT LINE {highlight_line}"
    return f"{header}\n{content}"


def _extract_local_imports(source: str, source_path: Path, repo_dir: Path) -> list[Path]:
    """Python/JS 소스에서 로컬 import를 추출하고 파일 경로로 변환."""
    found: list[Path] = []
    ext = source_path.suffix.lower()

    if ext == ".py":
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module = ""
                    if isinstance(node, ast.ImportFrom) and node.module:
                        module = node.module
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            module = alias.name
                    if module:
                        resolved = _py_module_to_path(module, source_path, repo_dir)
                        if resolved:
                            found.append(resolved)
        except SyntaxError:
            pass

    elif ext in {".ts", ".js"}:
        for m in re.finditer(r"""(?:import|require)\s*[\(\s]['"]([./][^'"]+)['"]""", source):
            imp = m.group(1)
            base = (source_path.parent / imp).resolve()
            for suffix in ["", ".ts", ".js", "/index.ts", "/index.js"]:
                candidate = Path(str(base) + suffix)
                if candidate.exists() and repo_dir in candidate.parents:
                    found.append(candidate)
                    break

    return [p for p in found if p.exists()]


def _py_module_to_path(module: str, source_path: Path, repo_dir: Path) -> Path | None:
    """Python 모듈 이름 → 파일 경로 변환. 로컬 모듈만."""
    parts = module.split(".")
    # 절대 경로 시도 (패키지 루트 기준)
    for root in [repo_dir, source_path.parent]:
        candidate = root.joinpath(*parts).with_suffix(".py")
        if candidate.exists():
            return candidate
        init = root.joinpath(*parts, "__init__.py")
        if init.exists():
            return init
    return None


def _find_callers(repo_dir: Path, sink_path: Path, exclude: set[Path]) -> list[Path]:
    """싱크 파일을 import하는 파일들을 찾아 반환 (역방향)."""
    module_name = sink_path.stem
    callers: list[Path] = []
    skip = {".git", "__pycache__", "node_modules", "dist", "build", "test", "spec"}

    for ext in ["*.py", "*.ts", "*.js"]:
        for f in repo_dir.rglob(ext):
            if any(p in skip for p in f.parts):
                continue
            if f in exclude or f == sink_path:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if module_name in content and ("import" in content or "require" in content):
                    callers.append(f)
            except Exception:
                continue

    # 라우터/앱/뷰 우선 정렬
    priority = {"route", "view", "app", "handler", "controller", "endpoint"}
    callers.sort(key=lambda p: -any(k in p.stem.lower() for k in priority))
    return callers[:5]
