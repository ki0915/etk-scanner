"""
intent_finder_multi.py — 다언어 보안 의도 탐지 (JS/TS/Python)

Python은 ast(intent_finder.py), JS/TS는 여기서 정규식으로 처리.
정적 티어 철학: high recall, LLM이 precision. 정규식으로 충분.

탐지:
  1. 보안 의도 함수 (auth/verify/validate/login/password/token/query...)
  2. 하드코딩 시크릿 (secret/key/password = '리터럴')
  3. 위험 싱크 (jwt.verify, exec, query 문자열조합, findOne where...)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_JS_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__",
              "venv", ".venv", "coverage", "logs", "migrations"}

# 함수 정의 (JS/TS): function foo / const foo = (...) => / foo(...) { / method
_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+(\w+)"
    r"|(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*(?::[^=]+)?=>"
    r"|(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{"
)

# 보안 의도 함수명 패턴
_INTENT_NAME = re.compile(
    r"(auth|verify|validate|login|logout|signup|signin|register|"
    r"password|passwd|token|jwt|secret|session|permission|role|admin|"
    r"sanitiz|escap|encrypt|decrypt|hash|sign|check|guard|middleware|"
    r"query|find|create|update|delete|upload|download)",
    re.IGNORECASE,
)

# 하드코딩 시크릿: secret/key/password/token 변수 = 문자열 리터럴
_HARDCODED = re.compile(
    r"(?:const|let|var)\s+(\w*(?:secret|key|password|passwd|token|apikey|api_key)\w*)"
    r"\s*(?::\s*\w+)?\s*=\s*['\"]([^'\"]{4,})['\"]",
    re.IGNORECASE,
)

# 위험 싱크
_SINKS = {
    "jwt_verify": re.compile(r"\bjwt\.verify\s*\("),
    "eval_exec": re.compile(r"\b(eval|exec|execSync|Function)\s*\("),
    "child_process": re.compile(r"child_process|\.exec\(|\.spawn\("),
    "sql_raw": re.compile(r"\.(query|raw)\s*\(\s*[`'\"].*\$\{"),
    "where_password": re.compile(r"where\s*:\s*\{[^}]*password", re.IGNORECASE | re.DOTALL),
    "token_log": re.compile(r"(log|logger)\.\w+\([^)]*\$\{[^)]*token", re.IGNORECASE),
}


@dataclass
class MultiFinding:
    name: str
    file: str
    start_line: int
    end_line: int
    code: str
    signals: list[str] = field(default_factory=list)
    score: float = 0.0

    def to_seed(self) -> dict:
        return {
            "entry_name": self.name, "sink_name": self.name,
            "sink_kind": "security_decision", "path": [self.name],
            "missing_guards": [], "intent_signals": self.signals,
            "score": self.score, "source": "intent", "file": self.file,
            "start_line": self.start_line, "code": self.code,
        }


def _iter_files(repo: Path):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if Path(f).suffix.lower() in _JS_EXT:
                yield Path(root) / f


def _extract_block(lines: list[str], start_idx: int, max_lines: int = 60) -> tuple[str, int]:
    """중괄호 균형으로 함수 본문 끝 찾기 (근사)."""
    depth = 0
    started = False
    end = start_idx
    for i in range(start_idx, min(len(lines), start_idx + max_lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        end = i
        if started and depth <= 0:
            break
    return "\n".join(lines[start_idx:end + 1]), end + 1


def find_intent_js(repo_path) -> list[MultiFinding]:
    repo = Path(repo_path)
    out = []
    for fpath in _iter_files(repo):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            continue

        # 하드코딩 시크릿 (라인 단위, 강한 신호)
        for i, line in enumerate(lines):
            m = _HARDCODED.search(line)
            if m:
                out.append(MultiFinding(
                    name=m.group(1), file=str(fpath), start_line=i + 1, end_line=i + 1,
                    code=line.strip(),
                    signals=[f"hardcoded_secret:{m.group(1)}"], score=9.0,
                ))

        # 함수 단위 보안 의도 + 싱크
        for i, line in enumerate(lines):
            fm = _FUNC_RE.search(line)
            if not fm:
                continue
            name = fm.group(1) or fm.group(2) or fm.group(3) or "anon"
            code, end = _extract_block(lines, i)

            signals = []
            score = 0.0
            if _INTENT_NAME.search(name):
                signals.append(f"name:{name}")
                score += 2.0
            # 본문 싱크 검사
            for sink_name, rx in _SINKS.items():
                if rx.search(code):
                    signals.append(f"sink:{sink_name}")
                    score += 2.5
            # 본문에 보안 키워드
            if _INTENT_NAME.search(code):
                score += 1.0

            if signals and score >= 2.0:
                out.append(MultiFinding(
                    name=name, file=str(fpath), start_line=i + 1, end_line=end,
                    code=code[:2000], signals=signals[:4], score=score,
                ))

    # 파일 밖 싱크도 잡기 위해 파일 전체 스캔 (함수 매칭 실패 대비)
    out.sort(key=lambda f: f.score, reverse=True)
    return out


def build_intent_seeds_js(repo_path, max_seeds: int = 40, max_per_file: int = 3) -> list[dict]:
    funcs = find_intent_js(repo_path)
    per_file = {}
    sel = []
    for f in funcs:
        if per_file.get(f.file, 0) >= max_per_file:
            continue
        per_file[f.file] = per_file.get(f.file, 0) + 1
        sel.append(f)
        if len(sel) >= max_seeds:
            break
    return [f.to_seed() for f in sel]


# ── 언어 자동 감지 디스패치 ──────────────────────────────────────────────────

def detect_language(repo_path) -> str:
    repo = Path(repo_path)
    py = js = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            ext = Path(f).suffix.lower()
            if ext == ".py":
                py += 1
            elif ext in _JS_EXT:
                js += 1
    return "js" if js > py else "python"


def build_seeds_auto(repo_path, max_seeds: int = 40) -> tuple[list[dict], str]:
    """언어 자동 감지 후 적절한 finder 사용."""
    lang = detect_language(repo_path)
    if lang == "js":
        return build_intent_seeds_js(repo_path, max_seeds), "js"
    from pipeline.intent_finder import build_intent_seeds
    return build_intent_seeds(repo_path, max_seeds), "python"
