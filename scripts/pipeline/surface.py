"""
surface.py - 공격 표면 식별

외부 입력을 받는 소스(Source)와 위험한 연산을 수행하는 싱크(Sink)를
AST 분석으로 자동 탐지합니다.

소스: HTTP 파라미터, CLI 인자, 파일 입력, 환경변수
싱크: SQL 실행, OS 명령, eval/exec, 역직렬화, 파일 쓰기
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class Source:
    """외부 입력점 — 공격자가 제어할 수 있는 값이 들어오는 곳."""
    file_path: str
    func_name: str
    line: int
    kind: str       # "http_param" | "cli_arg" | "env_var" | "file_input" | "socket"
    detail: str     # 구체적인 코드 패턴


@dataclass
class Sink:
    """위험 연산 — 취약점이 터지는 지점."""
    file_path: str
    func_name: str
    line: int
    kind: str       # "sql" | "cmd" | "eval" | "deserialize" | "file_write" | "template"
    detail: str


# ── 소스 패턴 ────────────────────────────────────────────────────────────────

# request.args.get / request.GET / request.POST / request.form / request.json
_HTTP_PARAM_ATTRS = {
    "args", "form", "data", "json", "files", "headers", "cookies",
    "GET", "POST", "PUT", "body", "query_params", "path_params",
}
_HTTP_OBJECTS = {
    "request", "req",
}

# sys.argv, input(), os.environ
_CLI_FUNCS = {"input"}
_CLI_ATTRS = {"argv"}
_ENV_ATTRS = {"environ"}


def _current_func(node: ast.AST, tree: ast.Module) -> str:
    """노드를 감싸는 가장 가까운 함수 이름 반환."""
    for parent in ast.walk(tree):
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(parent):
                if child is node:
                    return parent.name
    return "<module>"


def find_sources(path: Path, tree: ast.Module) -> list[Source]:
    sources = []
    fpath = str(path)

    for node in ast.walk(tree):
        func = _current_func(node, tree)
        lineno = getattr(node, "lineno", 0)

        # request.X 패턴
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name)
                    and node.value.id in _HTTP_OBJECTS
                    and node.attr in _HTTP_PARAM_ATTRS):
                sources.append(Source(
                    file_path=fpath, func_name=func, line=lineno,
                    kind="http_param",
                    detail=f"{node.value.id}.{node.attr}",
                ))
            # sys.argv
            elif (isinstance(node.value, ast.Name)
                  and node.value.id == "sys"
                  and node.attr in _CLI_ATTRS):
                sources.append(Source(
                    file_path=fpath, func_name=func, line=lineno,
                    kind="cli_arg", detail="sys.argv",
                ))
            # os.environ
            elif (isinstance(node.value, ast.Name)
                  and node.value.id == "os"
                  and node.attr in _ENV_ATTRS):
                sources.append(Source(
                    file_path=fpath, func_name=func, line=lineno,
                    kind="env_var", detail="os.environ",
                ))

        # input()
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _CLI_FUNCS:
                sources.append(Source(
                    file_path=fpath, func_name=func, line=lineno,
                    kind="cli_arg", detail="input()",
                ))

    return sources


# ── 싱크 패턴 ────────────────────────────────────────────────────────────────

_SQL_METHODS = {"execute", "executemany", "raw", "query", "filter_by"}
_CMD_FUNCS   = {"system", "popen", "execv", "execve"}
_CMD_METHODS = {"run", "call", "check_call", "check_output", "Popen"}
_EVAL_FUNCS  = {"eval", "exec", "compile", "__import__"}
_DESER_FUNCS = {"loads", "load"}
_DESER_MODS  = {"pickle", "marshal", "shelve"}
_YAML_UNSAFE = {"load"}


def find_sinks(path: Path, tree: ast.Module) -> list[Sink]:
    sinks = []
    fpath = str(path)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = _current_func(node, tree)
        lineno = getattr(node, "lineno", 0)

        # eval / exec / compile
        if isinstance(node.func, ast.Name) and node.func.id in _EVAL_FUNCS:
            sinks.append(Sink(
                file_path=fpath, func_name=func_name, line=lineno,
                kind="eval", detail=node.func.id + "()",
            ))

        elif isinstance(node.func, ast.Attribute):
            method = node.func.attr
            obj_name = ""
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id

            # cursor.execute / session.execute / db.raw …
            if method in _SQL_METHODS:
                sinks.append(Sink(
                    file_path=fpath, func_name=func_name, line=lineno,
                    kind="sql", detail=f"{obj_name}.{method}()",
                ))

            # subprocess.run / Popen …
            elif method in _CMD_METHODS:
                # shell=True 인지 확인
                has_shell = any(
                    isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords if kw.arg == "shell"
                )
                sinks.append(Sink(
                    file_path=fpath, func_name=func_name, line=lineno,
                    kind="cmd",
                    detail=f"{obj_name}.{method}(shell={'True' if has_shell else '?'})",
                ))

            # os.system / os.popen
            elif method in _CMD_FUNCS:
                sinks.append(Sink(
                    file_path=fpath, func_name=func_name, line=lineno,
                    kind="cmd", detail=f"{obj_name}.{method}()",
                ))

            # pickle.loads / marshal.loads
            elif method in _DESER_FUNCS and obj_name in _DESER_MODS:
                sinks.append(Sink(
                    file_path=fpath, func_name=func_name, line=lineno,
                    kind="deserialize", detail=f"{obj_name}.{method}()",
                ))

            # yaml.load (safe_load 제외)
            elif method in _YAML_UNSAFE and obj_name == "yaml":
                sinks.append(Sink(
                    file_path=fpath, func_name=func_name, line=lineno,
                    kind="deserialize", detail="yaml.load() (potentially unsafe)",
                ))

            # open() with write mode
            elif method == "open" or (isinstance(node.func, ast.Name)
                                       and getattr(node.func, "id", "") == "open"):
                args = node.args
                keywords = {kw.arg: kw.value for kw in node.keywords}
                mode_arg = (args[1] if len(args) > 1 else keywords.get("mode"))
                if mode_arg and isinstance(mode_arg, ast.Constant):
                    if any(c in str(mode_arg.value) for c in ("w", "a", "x")):
                        sinks.append(Sink(
                            file_path=fpath, func_name=func_name, line=lineno,
                            kind="file_write", detail=f"open(..., '{mode_arg.value}')",
                        ))

        # open() 전역 함수
        elif isinstance(node.func, ast.Name) and node.func.id == "open":
            args = node.args
            keywords = {kw.arg: kw.value for kw in node.keywords}
            mode_arg = (args[1] if len(args) > 1 else keywords.get("mode"))
            if mode_arg and isinstance(mode_arg, ast.Constant):
                if any(c in str(mode_arg.value) for c in ("w", "a", "x")):
                    sinks.append(Sink(
                        file_path=fpath, func_name=func_name, line=lineno,
                        kind="file_write", detail=f"open(..., '{mode_arg.value}')",
                    ))

    return sinks


# ── 전체 레포 스캔 ─────────────────────────────────────────────────────────

def scan_attack_surface(repo_path: str | Path) -> tuple[list[Source], list[Sink]]:
    """레포 전체에서 소스와 싱크를 추출합니다."""
    repo = Path(repo_path)
    all_sources: list[Source] = []
    all_sinks: list[Sink] = []

    for fpath in repo.rglob("*.py"):
        # 테스트/빌드 제외
        parts = set(fpath.parts)
        if parts & {"tests", "test", ".git", "__pycache__", "node_modules",
                    "venv", ".venv", "docs", "cookbook", "migrations"}:
            continue
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        all_sources.extend(find_sources(fpath, tree))
        all_sinks.extend(find_sinks(fpath, tree))

    return all_sources, all_sinks
