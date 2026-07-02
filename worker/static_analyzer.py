"""
Stage 1: LLM 호출 없이 AST + Regex로 의심 코드 경로만 추출.
소스(사용자 입력) → 싱크(위험 함수) 연결 경로가 없으면 LLM 호출 자체를 하지 않는다.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


# ── 위험 싱크 정의 ──────────────────────────────────────────────────────────

SINKS: dict[str, list[str]] = {
    "RCE": [
        "eval", "exec", "compile", "__import__",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen", "os.execv",
        "pickle.loads", "pickle.load",
        "yaml.load", "yaml.unsafe_load",
        "marshal.loads",
    ],
    "SQLI": [
        "execute", "executemany", "raw", "extra",
        "RawSQL", "cursor.execute",
    ],
    "LFI": [
        "open", "read_text", "read_bytes",
        "os.path.join", "pathlib.Path",
        "send_file", "send_from_directory",
    ],
    "SSRF": [
        "requests.get", "requests.post", "requests.put",
        "urllib.request.urlopen", "httpx.get", "httpx.post",
        "aiohttp.ClientSession",
    ],
    "AFO": [
        "open", "write", "write_text", "write_bytes",
        "shutil.copy", "shutil.move",
    ],
    "DESERIALIZE": [
        "pickle.loads", "pickle.load",
        "yaml.load", "yaml.unsafe_load",
        "json.loads",  # json 자체는 안전하나 후속 eval 체크
        "marshal.loads", "shelve.open",
    ],
    "REDOS": [],  # 정규식 패턴으로 별도 처리
}

# ── 사용자 입력 소스 ────────────────────────────────────────────────────────

SOURCE_PATTERNS = [
    # Python web frameworks
    r"request\.(args|form|json|data|files|values|cookies|headers|get_json)\b",
    r"flask\.request", r"fastapi\.Request",
    # 함수 파라미터에서 오는 외부 입력 힌트
    r"\bquery\b", r"\bpayload\b", r"\buser_input\b",
    # npm/node 패턴 (JS 분석 시)
    r"req\.(body|query|params|headers)\b",
    r"process\.argv",
]

# ── ReDoS 위험 정규식 패턴 ──────────────────────────────────────────────────

REDOS_PATTERNS = [
    r"re\.compile\(['\"].*(\+|\*|\{).*(\+|\*|\{).*['\"]\)",  # 중첩 반복
    r"\(\.\*\)\+", r"\(\.\+\)\+",                            # (.*)+
    r"\([^)]*\+[^)]*\)\*",                                   # (a+)*
]


@dataclass
class SuspiciousPath:
    file: str
    vuln_type: str
    sink_name: str
    sink_line: int
    source_hint: str          # 어떤 소스가 연결될 가능성이 있는지
    code_snippet: str         # 싱크 주변 ±5줄
    function_name: str = ""   # 싱크가 속한 함수
    confidence_hint: float = 0.5


@dataclass
class StaticAnalysisResult:
    file: str
    suspicious_paths: list[SuspiciousPath] = field(default_factory=list)
    has_user_input: bool = False
    file_summary: str = ""    # 파일 크기, 함수 수 등 메타 정보
    skipped: bool = False     # 소스-싱크 연결 없으면 True → LLM 생략


class PythonStaticAnalyzer:
    def analyze_file(self, path: Path) -> StaticAnalysisResult:
        result = StaticAnalysisResult(file=str(path))
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            result.skipped = True
            return result

        lines = source.splitlines()
        result.has_user_input = self._has_user_input(source)
        result.file_summary = self._summarize(source, lines)

        # 소스(입력점)가 없으면 분석 불필요
        if not result.has_user_input:
            result.skipped = True
            return result

        try:
            tree = ast.parse(source)
        except SyntaxError:
            result.skipped = True
            return result

        func_map = self._build_function_map(tree)

        for vuln_type, sinks in SINKS.items():
            if vuln_type == "REDOS":
                continue
            for node in ast.walk(tree):
                sink_name = self._match_sink(node, sinks)
                if not sink_name:
                    continue
                line = getattr(node, "lineno", 0)
                snippet = self._snippet(lines, line)
                # 스니펫 안에 사용자 입력 힌트가 있는지 확인
                source_hint = self._find_source_hint(snippet)
                if not source_hint:
                    # 같은 함수 내 소스 힌트도 확인
                    fn_name = func_map.get(line, "")
                    fn_body = self._get_function_body(tree, fn_name, lines)
                    source_hint = self._find_source_hint(fn_body)

                if source_hint:
                    result.suspicious_paths.append(SuspiciousPath(
                        file=str(path),
                        vuln_type=vuln_type,
                        sink_name=sink_name,
                        sink_line=line,
                        source_hint=source_hint,
                        code_snippet=snippet,
                        function_name=func_map.get(line, ""),
                        confidence_hint=0.6,
                    ))

        # ReDoS 패턴 검사
        for pattern in REDOS_PATTERNS:
            for m in re.finditer(pattern, source):
                line_no = source[:m.start()].count("\n") + 1
                if self._has_user_input_near(lines, line_no):
                    result.suspicious_paths.append(SuspiciousPath(
                        file=str(path),
                        vuln_type="REDOS",
                        sink_name="re.compile",
                        sink_line=line_no,
                        source_hint="regex with user input",
                        code_snippet=self._snippet(lines, line_no),
                        confidence_hint=0.5,
                    ))

        if not result.suspicious_paths:
            result.skipped = True

        return result

    # ── 내부 헬퍼 ──────────────────────────────────────────────────────────

    def _has_user_input(self, source: str) -> bool:
        return any(re.search(p, source) for p in SOURCE_PATTERNS)

    def _match_sink(self, node: ast.AST, sinks: list[str]) -> str:
        """AST 노드가 위험 싱크 호출인지 확인하고 싱크명 반환."""
        if not isinstance(node, ast.Call):
            return ""
        name = self._call_name(node)
        for sink in sinks:
            if "." in sink:
                # 정확한 모듈.함수 매칭: requests.get, pickle.loads 등
                # name이 sink 자체이거나 sink로 끝나야 함 (alias 허용)
                # 단, dict.get / json.loads 같은 일반 메서드는 제외
                obj, method = sink.rsplit(".", 1)
                call_parts = name.rsplit(".", 1)
                if len(call_parts) == 2:
                    call_obj, call_method = call_parts
                    # 메서드명 일치 + 객체명이 sink 객체와 같거나 알려진 별칭
                    if call_method == method and (
                        call_obj == obj
                        or call_obj.endswith(obj.split(".")[-1])  # import alias
                    ):
                        return sink
            else:
                # 단순 함수명: eval, exec 등
                if name == sink or name.split(".")[-1] == sink:
                    return sink
        return ""

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return ".".join(reversed(parts))
        return ""

    def _snippet(self, lines: list[str], line_no: int, context: int = 5) -> str:
        start = max(0, line_no - context - 1)
        end = min(len(lines), line_no + context)
        return "\n".join(
            f"{i+1}: {lines[i]}" for i in range(start, end)
        )

    def _find_source_hint(self, text: str) -> str:
        for p in SOURCE_PATTERNS:
            m = re.search(p, text)
            if m:
                return m.group(0)
        return ""

    def _has_user_input_near(self, lines: list[str], line_no: int, window: int = 10) -> bool:
        snippet = self._snippet(lines, line_no, window)
        return bool(self._find_source_hint(snippet))

    def _build_function_map(self, tree: ast.AST) -> dict[int, str]:
        """줄 번호 → 소속 함수명 매핑."""
        mapping: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for lineno in range(node.lineno, getattr(node, "end_lineno", node.lineno) + 1):
                    mapping[lineno] = node.name
        return mapping

    def _get_function_body(self, tree: ast.AST, fn_name: str, lines: list[str]) -> str:
        if not fn_name:
            return ""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == fn_name:
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                return "\n".join(lines[start:end])
        return ""

    def _summarize(self, source: str, lines: list[str]) -> str:
        try:
            tree = ast.parse(source)
            fn_count = sum(
                1 for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            cls_count = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
        except Exception:
            fn_count = cls_count = 0
        return f"{len(lines)} lines, {fn_count} functions, {cls_count} classes"


# ── JS/TS 싱크 패턴 ────────────────────────────────────────────────────────

JS_SINKS: dict[str, list[re.Pattern]] = {
    "RCE": [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"child_process|exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\("),
        re.compile(r"require\s*\(\s*[`'\"]child_process"),
    ],
    "SQLI": [
        re.compile(r"\.query\s*\(\s*[`'\"]?\s*\$\{"),          # query(`SELECT ${userInput}`)
        re.compile(r"\.query\s*\(\s*[`'\"][^)]*\+\s*\w"),      # query("SELECT " + input)
        re.compile(r"sequelize\.query\s*\("),
        re.compile(r"knex\.raw\s*\("),
        re.compile(r"\.raw\s*\(\s*[`'\"]?\s*\$\{"),
    ],
    "LFI": [
        re.compile(r"fs\.readFile\s*\("),
        re.compile(r"fs\.readFileSync\s*\("),
        re.compile(r"path\.join\s*\([^)]*req\."),
        re.compile(r"res\.sendFile\s*\("),
        re.compile(r"res\.download\s*\("),
    ],
    "SSRF": [
        re.compile(r"\bfetch\s*\(\s*(?:req\.|`|\$\{)"),
        re.compile(r"axios\.(get|post|put|delete)\s*\(\s*(?:req\.|`|\$\{)"),
        re.compile(r"https?\.request\s*\("),
    ],
    "AFO": [
        re.compile(r"fs\.writeFile\s*\("),
        re.compile(r"fs\.writeFileSync\s*\("),
        re.compile(r"fs\.appendFile\s*\("),
        re.compile(r"multer\s*\("),                             # 파일 업로드
    ],
    "HARDCODED_SECRET": [
        re.compile(r"(?:secret|secretKey|privateKey|apiKey|password)\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
        re.compile(r"jwt\.sign\s*\([^,]+,\s*['\"][^'\"]+['\"]"),  # jwt.sign(payload, 'hardcoded')
    ],
    "IDOR": [
        re.compile(r"where:\s*\{[^}]*id:\s*req\.(body|params|query)"),
        re.compile(r"findOne\s*\(\s*\{[^}]*:\s*req\."),
        re.compile(r"findById\s*\(\s*req\."),
    ],
    "REDOS": [
        re.compile(r"new\s+RegExp\s*\(\s*(?:req\.|`|\$\{)"),   # 사용자 입력으로 정규식 생성
        re.compile(r"\.match\s*\(\s*new\s+RegExp"),
    ],
}

JS_SOURCES = [
    re.compile(r"req\.(body|query|params|headers|cookies)\b"),
    re.compile(r"request\.(body|query|params|headers)\b"),
    re.compile(r"ctx\.(query|params|request\.body)\b"),         # Koa
    re.compile(r"event\.(body|queryStringParameters)\b"),       # Lambda
    re.compile(r"process\.argv\b"),
]

JS_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".next",
    "coverage", "__tests__", "test", "tests", "spec", "docs",
}


class JavaScriptStaticAnalyzer:
    """JS/TS 파일을 regex 기반으로 분석. AST 없이 패턴 매칭만 사용."""

    def analyze_file(self, path: Path) -> StaticAnalysisResult:
        result = StaticAnalysisResult(file=str(path))
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            result.skipped = True
            return result

        lines = source.splitlines()
        result.has_user_input = self._has_user_input(source)
        result.file_summary = f"{len(lines)} lines"

        for vuln_type, patterns in JS_SINKS.items():
            for pattern in patterns:
                for m in pattern.finditer(source):
                    line_no = source[:m.start()].count("\n") + 1
                    snippet = self._snippet(lines, line_no)

                    # HARDCODED_SECRET는 소스(user input) 없어도 탐지
                    if vuln_type == "HARDCODED_SECRET":
                        result.suspicious_paths.append(SuspiciousPath(
                            file=str(path),
                            vuln_type=vuln_type,
                            sink_name=m.group(0)[:60],
                            sink_line=line_no,
                            source_hint="hardcoded value",
                            code_snippet=snippet,
                            confidence_hint=0.8,
                        ))
                        continue

                    # 나머지는 소스(사용자 입력)와 연결 여부 확인
                    source_hint = self._find_source_hint(snippet)
                    if not source_hint:
                        # 같은 라우터 핸들러 블록(±30줄) 내 소스 확인
                        wide = self._snippet(lines, line_no, context=30)
                        source_hint = self._find_source_hint(wide)

                    if source_hint or vuln_type in {"AFO", "SSRF"}:
                        result.suspicious_paths.append(SuspiciousPath(
                            file=str(path),
                            vuln_type=vuln_type,
                            sink_name=m.group(0)[:60],
                            sink_line=line_no,
                            source_hint=source_hint or "indirect",
                            code_snippet=snippet,
                            confidence_hint=0.65,
                        ))

        if not result.suspicious_paths:
            result.skipped = True
        return result

    def _has_user_input(self, source: str) -> bool:
        return any(p.search(source) for p in JS_SOURCES)

    def _find_source_hint(self, text: str) -> str:
        for p in JS_SOURCES:
            m = p.search(text)
            if m:
                return m.group(0)
        return ""

    def _snippet(self, lines: list[str], line_no: int, context: int = 5) -> str:
        start = max(0, line_no - context - 1)
        end = min(len(lines), line_no + context)
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))


def analyze_repo(repo_path: str) -> list[StaticAnalysisResult]:
    """저장소 전체를 스캔해 의심 파일만 반환. Python + JS/TS 모두 지원."""
    py_analyzer = PythonStaticAnalyzer()
    js_analyzer = JavaScriptStaticAnalyzer()
    results: list[StaticAnalysisResult] = []

    skip_dirs = {
        ".git", "__pycache__", ".venv", "venv",
        "node_modules", "dist", "build", ".next",
        "tests", "test", "spec", "docs", "coverage",
    }

    root = Path(repo_path)

    for ext, analyzer in [("*.py", py_analyzer), ("*.ts", js_analyzer), ("*.js", js_analyzer)]:
        for f in root.rglob(ext):
            if any(part in skip_dirs for part in f.parts):
                continue
            result = analyzer.analyze_file(f)
            if not result.skipped:
                results.append(result)

    return results
