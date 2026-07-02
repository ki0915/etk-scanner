"""
Claude API 클라이언트.

호출 구조 (3단계 분리):
  Stage 2 - triage()       : Haiku, 의심 경로 → 취약점 후보 선별
  Stage 3a - deep_analyze(): Sonnet, 실제 exploit 경로 + PoC 생성
  Stage 3b - da_review()   : Sonnet, DA 반박 검토 (별도 호출, 중립 프롬프트)
"""

import os
import re
import json
from pathlib import Path
from typing import Any
import anthropic
from pydantic import BaseModel

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass


HAIKU_MODEL  = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"

_SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "analysis.md"


class VulnFinding(BaseModel):
    vuln_type: str
    confidence: float
    affected_file: str
    affected_line: int | None = None
    description: str
    root_cause: str
    poc_sketch: str = ""

    model_config = {"populate_by_name": True}

    @classmethod
    def model_validate(cls, obj, **kwargs):
        # affected_line이 문자열로 올 경우 숫자만 추출
        if isinstance(obj, dict) and isinstance(obj.get("affected_line"), str):
            m = re.search(r"\d+", obj["affected_line"])
            obj["affected_line"] = int(m.group()) if m else None
        return super().model_validate(obj, **kwargs)


class DeepAnalysis(BaseModel):
    vuln_type: str
    confidence: float
    affected_file: str
    affected_line: int | None
    description: str
    root_cause: str
    poc_code: str
    cvss_vector: str
    cvss_score: float


class DAResult(BaseModel):
    da_survived: bool       # True = 취약점 유효, False = 거부
    rebuttal: str           # 반박 내용 (거부 이유 or "no strong rebuttal")
    final_confidence: float # DA 이후 조정된 confidence


class ClaudeClient:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._system_prompt = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")

    # ── Stage 2: Haiku Triage ──────────────────────────────────────────────

    def triage(self, suspicious_paths_text: str, readme_summary: str) -> list[VulnFinding]:
        """Haiku로 실제 취약점 가능성 1차 판단. confidence < 0.5 필터링."""
        user_msg = f"""README summary: {readme_summary}

SUSPICIOUS CODE PATHS:
{suspicious_paths_text}

You are a security researcher. For each code path, assess whether it is a real, exploitable vulnerability.
Be accurate — neither over-report nor under-report.

Respond with ONLY a valid JSON array. Empty array [] if nothing is exploitable.

[
  {{
    "vuln_type": "RCE",
    "confidence": 0.8,
    "affected_file": "pkg/core.py",
    "affected_line": 42,
    "description": "one sentence describing the issue",
    "root_cause": "why this is vulnerable",
    "poc_sketch": "how an attacker would exploit this"
  }}
]"""
        resp = self.client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=2048,
            system=[{"type": "text", "text": self._system_prompt,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()
        data = self._parse_json_array(raw)
        return [VulnFinding.model_validate(item) for item in data
                if item.get("confidence", 0) >= 0.5]

    # ── Stage 3a: Sonnet Deep Analysis + PoC (tool_use로 JSON 강제) ─────────

    _ANALYZE_TOOL = {
        "name": "report_vulnerability",
        "description": "Report the vulnerability analysis result with PoC",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type":     {"type": "string"},
                "confidence":    {"type": "number", "minimum": 0, "maximum": 1},
                "affected_file": {"type": "string"},
                "affected_line": {"type": ["integer", "null"]},
                "description":   {"type": "string"},
                "root_cause":    {"type": "string"},
                "poc_code":      {"type": "string"},
                "cvss_vector":   {"type": "string"},
                "cvss_score":    {"type": "number"},
            },
            "required": ["vuln_type", "confidence", "affected_file",
                         "description", "root_cause", "poc_code",
                         "cvss_vector", "cvss_score"],
        },
    }

    def deep_analyze(
        self,
        finding: VulnFinding,
        file_content: str,
        package_name: str,
        package_version: str,
    ) -> DeepAnalysis | None:
        user_msg = f"""Package: {package_name}=={package_version}
Vulnerability type: {finding.vuln_type}
File: {finding.affected_file} (line {finding.affected_line})
Initial finding: {finding.description}

=== SOURCE CODE (+ call chain context) ===
{file_content}

Tasks:
1. Trace the FULL code path from external input to the vulnerable sink across all provided files.
2. Write a STANDALONE PoC script that:
   - Does NOT start a web server. Import and call the vulnerable function DIRECTLY.
   - Example for pickle RCE:
       import pickle, os
       class Exploit:
           def __reduce__(self): return (os.system, ("id",))
       output = pickle.loads(pickle.dumps(Exploit()))
       print(f"VULNERABLE: command executed, exit={{output}}")
   - When exploit succeeds, print exactly: VULNERABLE: <evidence of execution>
   - If not exploitable, set confidence < 0.5 and do NOT print VULNERABLE:
3. Call report_vulnerability with your findings."""

        resp = self.client.messages.create(
            model=SONNET_MODEL,
            max_tokens=4096,
            system=[{"type": "text", "text": self._system_prompt,
                     "cache_control": {"type": "ephemeral"}}],
            tools=[self._ANALYZE_TOOL],
            tool_choice={"type": "any"},
            messages=[{
                "role": "user",
                "content": [{"type": "text", "text": user_msg,
                              "cache_control": {"type": "ephemeral"}}],
            }],
        )

        for block in resp.content:
            if block.type == "tool_use" and block.name == "report_vulnerability":
                data = block.input
                conf = float(data.get("confidence", 0))
                print(f"    [DEBUG] Sonnet confidence={conf:.2f}")
                if conf < 0.4:
                    return None
                try:
                    return DeepAnalysis(**data)
                except Exception as e:
                    print(f"    [DEBUG] 모델 생성 실패: {e}")
                    return None

        print("    [DEBUG] tool_use 블록 없음")
        return None

    # ── Stage 3b: DA Review (별도 호출, 중립 프롬프트) ─────────────────────

    def da_review(
        self,
        analysis: DeepAnalysis,
        file_content: str,
        package_name: str,
    ) -> DAResult:
        """
        Devil's Advocate 검토.
        핵심: 거부를 유도하는 게 아니라 중립적으로 검토.
        실제 exploit이 가능하면 da_survived=True.
        """
        user_msg = f"""You are reviewing a vulnerability report for {package_name}.

Vulnerability: {analysis.vuln_type}
Description: {analysis.description}
Root cause: {analysis.root_cause}
CVSS Score: {analysis.cvss_score}

PoC code:
```python
{analysis.poc_code}
```

Relevant source code:
{file_content[:3000]}

Review this report objectively. Consider:
1. Is the PoC code actually valid and would it work?
2. Is there a real attack path from external input to the vulnerable code?
3. Are there mitigations already in place (e.g. auth checks, sandboxing)?
4. Is this a known/already-patched issue?

Rules:
- If the PoC is valid AND there's a real attack path AND no effective mitigations: da_survived=true
- If the PoC is invalid OR the attack path is blocked OR this is already patched: da_survived=false
- Do NOT reject just because it requires specific conditions — most real CVEs do.

Respond with ONLY this JSON:
{{
  "da_survived": true,
  "rebuttal": "brief note on why it survives or fails",
  "final_confidence": 0.0
}}"""
        resp = self.client.messages.create(
            model=SONNET_MODEL,
            max_tokens=1024,
            system=[{"type": "text", "text": self._system_prompt,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()
        try:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            data = json.loads(m.group(0)) if m else {}
            return DAResult(**data)
        except Exception:
            return DAResult(da_survived=True, rebuttal="parse error", final_confidence=analysis.confidence)

    # ── 라이브러리 직접 분석 모드 (Stage 1 우회) ──────────────────────────

    def analyze_library(
        self,
        file_content: str,
        file_path: str,
        package_name: str,
        readme_summary: str,
    ) -> list[VulnFinding]:
        """
        Stage 1(정적 분석)에서 아무것도 못 잡은 파서/유틸 라이브러리용.
        Haiku에게 파일 전체를 직접 주고 취약점을 찾게 함.
        """
        user_msg = f"""Package: {package_name}
File: {file_path}
README: {readme_summary}

=== SOURCE CODE ===
{file_content[:8000]}

This is a library (not a web app), so there are no explicit request.body patterns.
Analyze this code directly for security vulnerabilities:
- Logic bugs in parsing / boundary handling
- Resource exhaustion (no limits on input size/count)
- Type confusion or unexpected input handling
- Path traversal in file operations
- Any other exploitable issue

Respond with ONLY a valid JSON array. Empty array [] if nothing found.
[
  {{
    "vuln_type": "DoS",
    "confidence": 0.75,
    "affected_file": "{file_path}",
    "affected_line": 42,
    "description": "one sentence",
    "root_cause": "why vulnerable",
    "poc_sketch": "how to trigger"
  }}
]"""
        resp = self.client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=2048,
            system=[{"type": "text", "text": self._system_prompt,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()
        data = self._parse_json_array(raw)
        return [VulnFinding.model_validate(item) for item in data
                if item.get("confidence", 0) >= 0.5]

    # ── README 요약 ────────────────────────────────────────────────────────

    def summarize_readme(self, readme_text: str) -> str:
        resp = self.client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": (
                "Security researcher perspective: summarize this package's attack surface "
                "in 3-5 lines. Focus on: networking, external input handling, file I/O, "
                f"serialization.\n\nREADME:\n{readme_text[:3000]}"
            )}],
        )
        return resp.content[0].text.strip()

    # ── JSON 파싱 헬퍼 ─────────────────────────────────────────────────────

    @staticmethod
    def _parse_json_array(raw: str) -> list:
        try:
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            pass
        block = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.DOTALL)
        if block:
            try:
                return json.loads(block.group(1))
            except json.JSONDecodeError:
                pass
        for candidate in sorted(re.findall(r"\[.*?\]", raw, re.DOTALL), key=len, reverse=True):
            try:
                result = json.loads(candidate)
                if isinstance(result, list):
                    return result
            except json.JSONDecodeError:
                continue
        return []
