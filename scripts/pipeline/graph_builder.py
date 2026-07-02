"""
graph_builder.py — Stage 0: 콜 그래프 구축 → graph.db

레포의 Python 파일을 전부 AST 파싱해서
nodes / edges / tags 테이블을 SQLite에 저장한다.

nodes: 함수/메서드 하나
edges: caller → callee 호출 관계
tags : entry(진입점) / gate(권한체크) / sink(위험연산)
"""

from __future__ import annotations

import ast
import os
import sqlite3
from pathlib import Path
from typing import Iterator

import yaml

# ── config 로드 ───────────────────────────────────────────────────────────────

def _load_yaml(name: str) -> dict:
    p = Path(__file__).parent.parent.parent / "config" / name
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── 진입점 탐지 패턴 ──────────────────────────────────────────────────────────

_ENTRY_DECORATORS = {
    # Flask / FastAPI / Starlette
    "route", "get", "post", "put", "delete", "patch", "head",
    "api_view", "action",
    # Django
    "login_required", "permission_required",
    # Click / Typer (CLI)
    "command", "group",
    # 공통
    "endpoint", "handler",
}

_ENTRY_NAME_PREFIXES = ("view_", "handle_", "endpoint_", "api_")

# 라이브러리 공개 API: 언더스코어 없이 시작하는 최상위 함수 중
# 외부 데이터(data, content, text, xml, input, src, stream, path, filename)를 받는 것
_LIBRARY_INPUT_PARAMS = {
    "data", "content", "text", "xml", "xml_input", "input", "src",
    "stream", "path", "filename", "file", "s", "string",
    "body", "payload", "value", "obj", "input_dict", "d",
}
_SKIP_DIRS = {
    "tests", "test", ".git", "__pycache__", "node_modules",
    "venv", ".venv", "docs", "cookbook", "migrations", "enterprise",
    ".github", "ui", "static",
}

# ── 노드 추출 ─────────────────────────────────────────────────────────────────

def _iter_py_files(repo: Path) -> Iterator[Path]:
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield Path(root) / f


def _is_entry(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    # 1. HTTP 라우트 데코레이터
    for deco in node.decorator_list:
        name = ""
        if isinstance(deco, ast.Name):
            name = deco.id
        elif isinstance(deco, ast.Attribute):
            name = deco.attr
        elif isinstance(deco, ast.Call):
            if isinstance(deco.func, ast.Attribute):
                name = deco.func.attr
            elif isinstance(deco.func, ast.Name):
                name = deco.func.id
        if name.lower() in _ENTRY_DECORATORS:
            return True

    # 2. 핸들러/뷰 prefix
    if any(node.name.startswith(p) for p in _ENTRY_NAME_PREFIXES):
        return True

    # 3. 라이브러리 공개 API: 언더스코어 없이 시작 + 외부 입력 파라미터
    if not node.name.startswith("_"):
        params = {
            arg.arg for arg in node.args.args + node.args.posonlyargs
        }
        if params & _LIBRARY_INPUT_PARAMS:
            return True

    return False


def _get_calls(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    calls = []
    for n in ast.walk(func_node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                calls.append(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                calls.append(n.func.attr)
    return calls


# ── 게이트 / 싱크 태깅 ────────────────────────────────────────────────────────

def _build_gate_set(gates_cfg: dict) -> set[str]:
    names = gates_cfg.get("function_names", [])
    # "obj.method" 형태에서 method 부분만 추출
    result = set()
    for n in names:
        result.add(n.split(".")[-1])
    return result


def _is_sink(func_name: str, calls: list[str], sinks_cfg: dict) -> tuple[bool, str]:
    """(is_sink, kind) 반환."""
    sql_methods = set(sinks_cfg.get("sql", {}).get("methods", []))
    cmd_methods = set(sinks_cfg.get("cmd", {}).get("methods", []))
    cmd_funcs = set(sinks_cfg.get("cmd", {}).get("free_funcs", []))
    eval_funcs = set(sinks_cfg.get("eval_exec", {}).get("free_funcs", []))
    deser_methods = set(sinks_cfg.get("deserialize", {}).get("unsafe_methods", []))
    yaml_unsafe = set(sinks_cfg.get("deserialize", {}).get("yaml_unsafe", []))
    tmpl_methods = set(sinks_cfg.get("template", {}).get("methods", []))
    xml_out_methods = set(sinks_cfg.get("xml_output", {}).get("methods", []))
    xml_out_funcs = set(sinks_cfg.get("xml_output", {}).get("free_funcs", []))
    xml_parse_methods = set(sinks_cfg.get("xml_parse", {}).get("methods", []))

    for call in calls:
        if call in sql_methods:
            return True, "sql"
        if call in cmd_methods or call in cmd_funcs:
            return True, "cmd"
        if call in eval_funcs:
            return True, "eval_exec"
        if call in deser_methods or call in yaml_unsafe:
            return True, "deserialize"
        if call == "open":
            return True, "file_write"
        if call in tmpl_methods:
            return True, "template"
        if call in xml_out_methods or call in xml_out_funcs:
            return True, "xml_output"
        if call in xml_parse_methods:
            return True, "xml_parse"
    return False, ""


# ── DB 초기화 ─────────────────────────────────────────────────────────────────

def _init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            file        TEXT NOT NULL,
            start_line  INTEGER,
            end_line    INTEGER,
            code        TEXT,
            is_entry    INTEGER DEFAULT 0,
            is_gate     INTEGER DEFAULT 0,
            is_sink     INTEGER DEFAULT 0,
            sink_kind   TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS edges (
            caller_id   INTEGER REFERENCES nodes(id),
            callee_name TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
        CREATE INDEX IF NOT EXISTS idx_edges_caller ON edges(caller_id);
    """)
    conn.commit()
    return conn


# ── 메인 빌더 ─────────────────────────────────────────────────────────────────

def build_graph(repo_path: str | Path, db_path: str | Path | None = None) -> Path:
    """
    레포를 파싱해서 graph.db를 생성하고 경로를 반환합니다.
    """
    repo = Path(repo_path)
    if db_path is None:
        db_path = Path(__file__).parent.parent.parent / "data" / "graph.db"
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists():
        db_path.unlink()

    gates_cfg = _load_yaml("gates.yaml")
    sinks_cfg = _load_yaml("sinks.yaml")
    gate_names = _build_gate_set(gates_cfg)

    conn = _init_db(db_path)
    parse_failures = []
    node_count = 0
    edge_count = 0

    for fpath in _iter_py_files(repo):
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()
            tree = ast.parse(source)
        except SyntaxError:
            parse_failures.append(str(fpath))
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            code = "\n".join(lines[start - 1:end])
            calls = _get_calls(node)

            is_entry = _is_entry(node)
            is_gate = node.name in gate_names
            is_sink_flag, sink_kind = _is_sink(node.name, calls, sinks_cfg)

            cur = conn.execute(
                """INSERT INTO nodes (name, file, start_line, end_line, code,
                   is_entry, is_gate, is_sink, sink_kind)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (node.name, str(fpath), start, end, code,
                 int(is_entry), int(is_gate), int(is_sink_flag), sink_kind),
            )
            node_id = cur.lastrowid
            node_count += 1

            for callee in set(calls):
                conn.execute(
                    "INSERT INTO edges (caller_id, callee_name) VALUES (?,?)",
                    (node_id, callee),
                )
                edge_count += 1

    conn.commit()
    conn.close()

    # 파싱 실패 기록
    log_path = db_path.parent / "parse_failures.log"
    log_path.write_text("\n".join(parse_failures), encoding="utf-8")

    print(f"  nodes: {node_count} | edges: {edge_count} | parse failures: {len(parse_failures)}")
    return db_path
