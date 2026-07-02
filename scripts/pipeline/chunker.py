"""
AST-based semantic code chunker.

For Python: extracts functions, methods, and classes as discrete chunks,
preserving surrounding context (imports, class header) so the LLM has
enough information without seeing the entire file.

For other languages (JS, TS, Go, etc.): falls back to line-window chunking
using heuristic boundaries (blank lines, brace depth).
"""

from __future__ import annotations

import ast
import os
import textwrap
from pathlib import Path
from typing import Iterator

from pipeline.models import CodeChunk

# Lines of import context prepended to every function/method chunk
IMPORT_CONTEXT_LINES = 30
# Max lines per non-Python chunk (line-window fallback)
MAX_CHUNK_LINES = 80
# Overlap between consecutive line-window chunks
CHUNK_OVERLAP = 10

PYTHON_EXTENSIONS = {".py", ".pyw"}
TEXT_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb",
    ".php", ".c", ".cpp", ".h", ".hpp", ".rs",
}


# ── Python chunker ────────────────────────────────────────────────────────────

def _source_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _node_code(lines: list[str], node: ast.AST) -> str:
    start = node.lineno - 1
    end = node.end_lineno  # type: ignore[attr-defined]
    return "\n".join(lines[start:end])


def _import_context(lines: list[str]) -> str:
    """Return the first IMPORT_CONTEXT_LINES lines that are imports/comments."""
    ctx = []
    for line in lines[:IMPORT_CONTEXT_LINES]:
        stripped = line.strip()
        if stripped.startswith(("import ", "from ", "#", '"""', "'''", "")):
            ctx.append(line)
        else:
            break
    return "\n".join(ctx)


def chunk_python(path: Path) -> Iterator[CodeChunk]:
    lines = _source_lines(path)
    source = "\n".join(lines)
    import_ctx = _import_context(lines)

    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Fall back to line-window chunking for unparseable files
        yield from chunk_by_lines(path, language="python")
        return

    rel_path = str(path)

    for node in ast.walk(tree):
        # Top-level functions and async functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip very short helpers (< 5 lines) — low signal
            if (node.end_lineno - node.lineno) < 5:  # type: ignore[attr-defined]
                continue
            code = _node_code(lines, node)
            yield CodeChunk(
                file_path=rel_path,
                chunk_type="function",
                name=node.name,
                code=code,
                start_line=node.lineno,
                end_line=node.end_lineno,  # type: ignore[attr-defined]
                context=import_ctx,
                language="python",
            )

        # Classes — yield the class header + each method separately
        elif isinstance(node, ast.ClassDef):
            # Class-level chunk (just the class body without methods)
            class_header_lines = []
            for i in range(node.lineno - 1, node.end_lineno):  # type: ignore[attr-defined]
                class_header_lines.append(lines[i])
                if i > node.lineno + 5:
                    break
            class_header = "\n".join(class_header_lines)

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if (item.end_lineno - item.lineno) < 5:  # type: ignore[attr-defined]
                        continue
                    code = _node_code(lines, item)
                    ctx = import_ctx + "\n\n" + class_header
                    yield CodeChunk(
                        file_path=rel_path,
                        chunk_type="method",
                        name=f"{node.name}.{item.name}",
                        code=code,
                        start_line=item.lineno,
                        end_line=item.end_lineno,  # type: ignore[attr-defined]
                        context=ctx,
                        language="python",
                    )


# ── Line-window fallback chunker ──────────────────────────────────────────────

def chunk_by_lines(path: Path, language: str = "") -> Iterator[CodeChunk]:
    """Slide a window of MAX_CHUNK_LINES over the file with CHUNK_OVERLAP."""
    lines = _source_lines(path)
    ext = path.suffix.lower()
    lang = language or ext.lstrip(".")

    total = len(lines)
    step = MAX_CHUNK_LINES - CHUNK_OVERLAP
    chunk_idx = 0

    for start in range(0, total, step):
        end = min(start + MAX_CHUNK_LINES, total)
        code = "\n".join(lines[start:end])
        if not code.strip():
            continue
        yield CodeChunk(
            file_path=str(path),
            chunk_type="module",
            name=f"{path.name}:block{chunk_idx}",
            code=code,
            start_line=start + 1,
            end_line=end,
            language=lang,
        )
        chunk_idx += 1
        if end == total:
            break


# ── Directory walker ──────────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".tox", "venv", ".venv",
    "env", "dist", "build", ".eggs",
    # test / docs / examples — low security signal, high token cost
    "tests", "test", "cookbook", "docs", "doc", "examples", "example",
    # infra / CI
    ".github", "helm", "terraform", "deploy", "migrations", "ci_cd",
    # frontend
    "ui", "static", "assets",
    # enterprise add-ons (separate billing boundary)
    "enterprise",
}


def iter_source_files(repo_path: Path) -> Iterator[Path]:
    for root, dirs, files in os.walk(repo_path):
        # Prune irrelevant directories in-place
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in PYTHON_EXTENSIONS | TEXT_EXTENSIONS:
                yield fpath


def chunk_repo(repo_path: str | Path, max_file_kb: int = 500) -> list[CodeChunk]:
    """
    Walk `repo_path` and return all semantic chunks.
    Files larger than `max_file_kb` KB are split by line-window only.
    """
    repo = Path(repo_path)
    chunks: list[CodeChunk] = []

    for fpath in iter_source_files(repo):
        try:
            size_kb = fpath.stat().st_size / 1024
        except OSError:
            continue

        if size_kb > max_file_kb:
            chunks.extend(chunk_by_lines(fpath))
            continue

        if fpath.suffix.lower() in PYTHON_EXTENSIONS:
            chunks.extend(chunk_python(fpath))
        else:
            chunks.extend(chunk_by_lines(fpath))

    return chunks
