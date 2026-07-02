"""
intent_finder.py — 분류 기준 전환: "위험 싱크" → "보안 의도 함수"

기존 싱크 기반 탐지는 SQL/eval 같은 명백한 위험 연산만 찾았다.
하지만 미지의 CVE 대부분은 싱크 없는 로직 버그다:
  - validators.ipv4(private=False): bool 반환 SSRF 판정 우회
  - datasette _facet: 권한 체크 누락
  - 검증/정규화/파싱 함수의 우회

이 모듈은 "보안 판단을 하는 함수"를 후보로 올린다.
그 함수의 보안 의도가 깨지는지는 에이전트(LLM)가 의미적으로 조사한다.

보안 의도 함수의 특징:
  1. 이름: validate/check/verify/is_*/sanitize/escape/normalize/parse/
          allow/deny/filter/clean/auth/secret/token/sign/decode/...
  2. bool 또는 판정값을 반환 (허용/거부 결정)
  3. 외부 입력을 받음
  4. docstring에 보안 관련 단어 (valid, safe, allow, private, public, trusted...)
  5. 표준 라이브러리를 재구현 (직접 만든 정규식/문자열 파싱)
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# 보안 판단 의도를 가진 함수명 패턴
_INTENT_NAME = re.compile(
    r"(valid|check|verify|ensure|assert|sanitiz|escap|normaliz|"
    r"allow|deny|forbid|authori|authentic|permission|"
    r"is_|has_|can_|_safe|_check|parse|decode|encode|unquote|"
    r"clean|filter|strip|quote|slug|token|secret|sign|verif|"
    r"trust|private|public|whitelist|blacklist|sandbox)",
    re.IGNORECASE,
)

# docstring/코드에서 보안 의도를 드러내는 단어
_SECURITY_WORDS = re.compile(
    r"\b(valid|invalid|safe|unsafe|allow|deny|private|public|trusted|"
    r"untrusted|sanitiz|escap|inject|bypass|secure|permission|forbidden|"
    r"whitelist|blacklist|malicious|attacker|exploit)\b",
    re.IGNORECASE,
)

# 외부 입력을 받는 파라미터 이름
_INPUT_PARAMS = {
    "value", "data", "input", "text", "s", "string", "url", "uri",
    "path", "host", "hostname", "domain", "email", "addr", "address",
    "ip", "token", "name", "content", "payload", "raw", "user_input",
    "arg", "param", "src", "target", "scheme",
}

_SKIP_DIRS = {
    "tests", "test", ".git", "__pycache__", "node_modules",
    "venv", ".venv", "docs", "cookbook", "migrations", "enterprise",
    ".github", "ui", "static", "examples",
}


@dataclass
class IntentFunc:
    """보안 판단 의도를 가진 함수 후보."""
    name: str
    file: str
    start_line: int
    end_line: int
    code: str
    signals: list[str] = field(default_factory=list)   # 왜 후보인지
    returns_bool: bool = False
    is_public_api: bool = False
    score: float = 0.0

    def to_seed(self) -> dict:
        return {
            "entry_name": self.name,
            "sink_name": self.name,          # 의도 함수 자체가 조사 대상
            "sink_kind": "security_decision",
            "path": [self.name],
            "missing_guards": [],
            "intent_signals": self.signals,
            "returns_bool": self.returns_bool,
            "is_public_api": self.is_public_api,
            "score": self.score,
            "source": "intent",
            "file": self.file,
            "start_line": self.start_line,
            "code": self.code,
        }


def _returns_bool_or_decision(node: ast.AST) -> bool:
    """함수가 bool/판정값을 반환하는가 (허용/거부 결정 신호)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Return) and n.value is not None:
            v = n.value
            if isinstance(v, ast.Constant) and isinstance(v.value, bool):
                return True
            if isinstance(v, ast.Compare):
                return True
            if isinstance(v, ast.BoolOp):
                return True
            # return not X
            if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not):
                return True
            # return re.match(...) / startswith(...)
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute):
                if v.func.attr in ("match", "search", "startswith", "endswith", "fullmatch"):
                    return True
    return False


def _has_handrolled_parsing(node: ast.AST) -> bool:
    """직접 만든 정규식/문자열 파싱 (표준 재구현 신호 → 우회 가능성)."""
    signals = 0
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr in ("startswith", "endswith", "split", "rsplit",
                                "strip", "lstrip", "rstrip", "count", "find",
                                "replace", "match", "search", "sub", "compile"):
                signals += 1
    return signals >= 2


def find_intent_functions(repo_path: str | Path) -> list[IntentFunc]:
    repo = Path(repo_path)
    results: list[IntentFunc] = []

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = Path(root) / fname
            try:
                source = fpath.read_text(encoding="utf-8", errors="replace")
                lines = source.splitlines()
                tree = ast.parse(source)
            except (SyntaxError, OSError):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                signals = []
                score = 0.0

                # 1. 이름 패턴
                if _INTENT_NAME.search(node.name):
                    signals.append(f"name:{node.name}")
                    score += 2.0

                # 2. 외부 입력 파라미터
                params = {a.arg for a in node.args.args + node.args.posonlyargs}
                input_params = params & _INPUT_PARAMS
                if input_params:
                    signals.append(f"input_param:{','.join(sorted(input_params))}")
                    score += 1.5

                # 3. bool/판정 반환
                returns_bool = _returns_bool_or_decision(node)
                if returns_bool:
                    signals.append("returns_decision")
                    score += 2.0

                # 4. docstring 보안 단어
                doc = ast.get_docstring(node) or ""
                sec_words = set(_SECURITY_WORDS.findall(doc.lower()))
                if sec_words:
                    signals.append(f"sec_doc:{','.join(sorted(sec_words)[:3])}")
                    score += 1.5

                # 5. 직접 만든 파싱 (표준 재구현)
                handrolled = _has_handrolled_parsing(node)
                if handrolled:
                    signals.append("handrolled_parsing")
                    score += 1.5

                is_public = not node.name.startswith("_")
                if is_public:
                    score += 0.5

                # 충분한 신호가 모인 함수만 후보로 (이름만으론 부족)
                # 최소: (이름 OR docstring) AND (입력 OR 판정 OR 파싱)
                name_or_doc = bool(_INTENT_NAME.search(node.name)) or bool(sec_words)
                behavior = bool(input_params) or returns_bool or handrolled
                if not (name_or_doc and behavior):
                    continue
                # 5줄 미만 trivial 제외
                end = getattr(node, "end_lineno", node.lineno)
                if end - node.lineno < 4:
                    continue

                results.append(IntentFunc(
                    name=node.name,
                    file=str(fpath),
                    start_line=node.lineno,
                    end_line=end,
                    code="\n".join(lines[node.lineno - 1:end]),
                    signals=signals,
                    returns_bool=returns_bool,
                    is_public_api=is_public,
                    score=score,
                ))

    results.sort(key=lambda f: f.score, reverse=True)
    return results


def build_intent_seeds(repo_path: str | Path, max_seeds: int = 20,
                       max_per_file: int = 2) -> list[dict]:
    """
    파일당 max_per_file개로 제한해 다양성 확보 + 비용 절감.
    (예: card.py의 8개 동일 구조 카드 검증 함수 → 2개만)
    """
    funcs = find_intent_functions(repo_path)
    per_file: dict[str, int] = {}
    selected = []
    for f in funcs:
        if per_file.get(f.file, 0) >= max_per_file:
            continue
        per_file[f.file] = per_file.get(f.file, 0) + 1
        selected.append(f)
        if len(selected) >= max_seeds:
            break
    return [f.to_seed() for f in selected]
