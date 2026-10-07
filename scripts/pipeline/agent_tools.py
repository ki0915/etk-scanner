"""
agent_tools.py — 탐색 에이전트가 사용하는 도구

에이전트는 이 도구들로 코드베이스를 능동 탐색한다:
  - read_function(name)   : 함수 소스 읽기
  - find_callers(name)    : 이 함수를 호출하는 곳
  - find_callees(name)    : 이 함수가 호출하는 것
  - grep_repo(pattern)    : 코드 검색
  - read_file(path, start, end) : 파일 특정 구간 읽기
  - run_poc(code)         : 실제 패키지로 PoC 실행 (격리 샌드박스)

graph.db(지도) + 실제 레포 파일을 백엔드로 사용.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
from pathlib import Path

from pipeline import sandbox

_BLOCKED_IMPORTS = {"socket", "urllib", "requests", "httpx", "aiohttp",
                    "paramiko", "ftplib", "smtplib", "telnetlib"}


class ToolBox:
    """에이전트 도구 모음. graph.db + repo 경로에 바인딩."""

    def __init__(self, db_path: str | Path, repo_path: str | Path, package: str = ""):
        self.db_path = Path(db_path)
        self.repo_path = Path(repo_path)
        self.package = package

    # ── 그래프 도구 ───────────────────────────────────────────────────────────

    def read_function(self, name: str) -> str:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT name, file, start_line, end_line, code, is_gate, is_sink, sink_kind "
            "FROM nodes WHERE name = ? LIMIT 5", (name,)
        ).fetchall()
        conn.close()
        if not rows:
            return f"(함수 '{name}'를 찾을 수 없음. grep_repo로 검색해보세요.)"
        out = []
        for r in rows:
            tags = []
            if r["is_gate"]: tags.append("GATE")
            if r["is_sink"]: tags.append(f"SINK:{r['sink_kind']}")
            tag_str = f" [{','.join(tags)}]" if tags else ""
            fname = Path(r["file"]).name
            out.append(
                f"# {r['name']}{tag_str} ({fname}:{r['start_line']}-{r['end_line']})\n"
                f"{r['code']}"
            )
        return "\n\n---\n\n".join(out)

    def find_callers(self, name: str) -> str:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT DISTINCT n.name, n.file, n.start_line
            FROM edges e JOIN nodes n ON e.caller_id = n.id
            WHERE e.callee_name = ? LIMIT 30
        """, (name,)).fetchall()
        conn.close()
        if not rows:
            return f"(아무도 '{name}'를 호출하지 않음)"
        return "\n".join(
            f"{r['name']} ({Path(r['file']).name}:{r['start_line']})" for r in rows
        )

    def find_callees(self, name: str) -> str:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        node = conn.execute("SELECT id FROM nodes WHERE name = ? LIMIT 1", (name,)).fetchone()
        if not node:
            conn.close()
            return f"(함수 '{name}' 없음)"
        rows = conn.execute(
            "SELECT DISTINCT callee_name FROM edges WHERE caller_id = ? LIMIT 50",
            (node["id"],)
        ).fetchall()
        conn.close()
        if not rows:
            return f"({name}이 호출하는 게 없음)"
        return ", ".join(r["callee_name"] for r in rows)

    def grep_repo(self, pattern: str, max_results: int = 20) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"(잘못된 정규식: {e})"
        results = []
        _skip = {"tests", "test", ".git", "__pycache__", "node_modules", "venv", ".venv"}
        for fpath in self.repo_path.rglob("*.py"):
            if set(fpath.parts) & _skip:
                continue
            try:
                for i, line in enumerate(fpath.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        results.append(f"{fpath.relative_to(self.repo_path)}:{i}: {line.strip()[:120]}")
                        if len(results) >= max_results:
                            return "\n".join(results) + f"\n(상위 {max_results}개만 표시)"
            except OSError:
                continue
        return "\n".join(results) if results else f"(패턴 '{pattern}' 매치 없음)"

    def read_file(self, rel_path: str, start: int = 1, end: int = 60) -> str:
        fpath = self.repo_path / rel_path
        if not fpath.exists():
            # 절대경로나 파일명만 준 경우 보정
            matches = list(self.repo_path.rglob(Path(rel_path).name))
            if matches:
                fpath = matches[0]
            else:
                return f"(파일 '{rel_path}' 없음)"
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            return f"(읽기 실패: {e})"
        start = max(1, start)
        end = min(len(lines), end)
        chunk = lines[start - 1:end]
        return "\n".join(f"{start+i}: {l}" for i, l in enumerate(chunk))

    # ── PoC 실행 도구 ─────────────────────────────────────────────────────────

    def run_poc(self, code: str, timeout: int = 10) -> str:
        """실제 패키지로 PoC 실행. 대상 import 강제, 네트워크 차단."""
        # 네트워크 코드 차단
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return f"SYNTAX_ERROR: {e}"
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in getattr(node, "names", [])]
                module = getattr(node, "module", "") or ""
                if any(n.split(".")[0] in _BLOCKED_IMPORTS for n in names) or \
                   module.split(".")[0] in _BLOCKED_IMPORTS:
                    return "BLOCKED: PoC contains network imports — not allowed."

        # 대상 패키지 import 강제
        if self.package:
            pkg_root = self.package.replace("-", "_").split(".")[0]
            imports_target = any(
                (isinstance(n, ast.Import) and any(a.name.split(".")[0] == pkg_root for a in n.names))
                or (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == pkg_root)
                for n in ast.walk(tree)
            )
            if not imports_target:
                return (f"REJECTED: PoC must `import {pkg_root}` and call the REAL function. "
                        f"Do not reimplement the logic — that proves nothing.")

        # 실행은 격리 컨테이너에서만 (호스트 실행·환경변수 상속 없음).
        # 위 import 검사는 빠른 피드백용이고, 실제 차단은 --network none 이 담당한다.
        try:
            result = sandbox.run_python(
                code, self.repo_path, sandbox.SandboxConfig(timeout=timeout))
        except Exception as e:
            return f"ERROR: {e}"
        return result.to_tool_text()

    # ── 디스패치 ──────────────────────────────────────────────────────────────

    def dispatch(self, name: str, args: dict) -> str:
        try:
            if name == "read_function":
                return self.read_function(args["name"])
            if name == "find_callers":
                return self.find_callers(args["name"])
            if name == "find_callees":
                return self.find_callees(args["name"])
            if name == "grep_repo":
                return self.grep_repo(args["pattern"], args.get("max_results", 20))
            if name == "read_file":
                return self.read_file(args["path"], args.get("start", 1), args.get("end", 60))
            if name == "run_poc":
                return self.run_poc(args["code"])
            return f"(알 수 없는 도구: {name})"
        except KeyError as e:
            return f"(필수 인자 누락: {e})"
        except Exception as e:
            return f"(도구 실행 오류: {e})"


# ── 도구 스키마 (Anthropic tool-use 형식) ─────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "read_function",
        "description": "Read the source code of a function by name. Returns code with GATE/SINK tags and file location.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Function name"}},
            "required": ["name"],
        },
    },
    {
        "name": "find_callers",
        "description": "Find all functions that call the given function. Use to trace how attacker input reaches a function.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "find_callees",
        "description": "List functions called by the given function. Use to see what a function does internally.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "grep_repo",
        "description": "Search the repository source with a regex. Use to find where a pattern/variable/check appears.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Python regex"},
                "max_results": {"type": "integer", "description": "default 20"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "read_file",
        "description": "Read specific lines of a source file (relative path or filename). Use for context around a function.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start": {"type": "integer"},
                "end": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "run_poc",
        "description": ("Execute a PoC script against the REAL installed package in an isolated sandbox. "
                        "The script MUST import the target package and call its real function — "
                        "reimplementing the logic is rejected. No network allowed. "
                        "Returns stdout/stderr. Use to confirm or refute the vulnerability."),
        "input_schema": {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Complete Python PoC script"}},
            "required": ["code"],
        },
    },
]
