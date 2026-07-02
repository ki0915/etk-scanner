"""
Claude API 래퍼.
Stage 2 (Haiku triage) → Stage 3a (Sonnet analyze) → Stage 3c (DA review) 순으로 호출.
"""

from __future__ import annotations
import json
import os
import re
from pathlib import Path

import time
import anthropic

from .models import DAResult, DeepAnalysis, VulnFinding

HAIKU  = "claude-haiku-4-5-20251001"
SONNET = "claude-sonnet-4-6"

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "analysis.md"


class LLMClient:
    def __init__(self):
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._system  = _PROMPT_PATH.read_text(encoding="utf-8")

    # ── 공통 헬퍼 ─────────────────────────────────────────────────────────────

    def _chat(self, model: str, user: str, max_tokens: int = 2048,
              _retry: int = 3) -> str:
        for attempt in range(_retry):
            try:
                resp = self._client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=[{"type": "text", "text": self._system,
                             "cache_control": {"type": "ephemeral"}}],
                    messages=[{"role": "user", "content": user}],
                )
                return resp.content[0].text.strip()
            except anthropic.RateLimitError:
                wait = 60 * (attempt + 1)   # 60s → 120s → 180s
                print(f"    Rate limit 도달 → {wait}s 대기 후 재시도...")
                time.sleep(wait)
        return ""

    @staticmethod
    def _parse_json_list(raw: str) -> list:
        for attempt in [
            lambda: json.loads(raw),
            lambda: json.loads(re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.DOTALL).group(1)),
            lambda: next(json.loads(c) for c in sorted(
                re.findall(r"\[.*?\]", raw, re.DOTALL), key=len, reverse=True
            ) if isinstance(json.loads(c), list)),
        ]:
            try:
                result = attempt()
                if isinstance(result, list):
                    return result
            except Exception:
                continue
        return []

    # ── Stage 2-alt: 테인트 경로 기반 가설 생성 ──────────────────────────────

    def hypothesize_paths(
        self,
        paths: list,            # list[TaintPath]
        readme_summary: str,
        batch_size: int = 4,
    ) -> list[VulnFinding]:
        """
        소스→싱크 경로를 배치로 묶어 Haiku에 전달.
        단순 청크 분석과 달리, 실제 데이터 흐름 경로를 주기 때문에
        "이 변수가 어디서 와서 어디서 문제를 일으키는지"를 LLM이 명확히 볼 수 있다.
        """
        all_findings: list[VulnFinding] = []
        total = len(paths)

        for i in range(0, total, batch_size):
            batch = paths[i : i + batch_size]
            batch_text = "\n\n---\n\n".join(p.to_prompt() for p in batch)
            print(f"    Haiku 경로 분석 {i//batch_size+1}/{(total+batch_size-1)//batch_size} ({len(batch)}개 경로)...")

            prompt = f"""You are a security researcher.
Package: {readme_summary}

Below are {len(batch)} TAINT PATHS — each shows the complete call chain
from where external user data ENTERS the code to where it reaches a potentially dangerous operation.

{batch_text}

Your task: For each taint path, answer:
1. Does attacker-controlled data actually flow from the SOURCE function to the SINK without being sanitized?
2. What specific input (HTTP header, body field, filename, etc.) carries the tainted value?
3. What is the exact dangerous outcome (arbitrary file write, command execution, DoS, etc.)?

A hypothesis is ONLY valid if:
- The tainted variable is NOT sanitized between source and sink
- The sink operation actually does something harmful with the tainted value
- A real HTTP request (or API call) can trigger this path

Respond with ONLY a JSON array ([] if no valid hypotheses):
[
  {{
    "vuln_type": "Path Traversal",
    "confidence": 0.85,
    "affected_file": "multipart/multipart.py",
    "affected_line": 500,
    "description": "Attacker-controlled filename from Content-Disposition reaches open() without sanitization",
    "root_cause": "file_name from parse_options_header flows to _get_disk_file → os.path.join → open() with no path check",
    "poc_sketch": "POST /upload with Content-Disposition: form-data; filename='../../../etc/evil'"
  }}
]"""

            raw  = self._chat(HAIKU, prompt, max_tokens=2048)
            data = self._parse_json_list(raw)
            findings = [
                VulnFinding.model_validate(d)
                for d in data
                if d.get("confidence", 0) >= 0.5
            ]
            all_findings.extend(findings)

        return all_findings

    # ── Stage 2: Haiku 가설 생성 ────────────────────────────────────────────
    #
    # 기존 방식: "이 코드가 취약한가?" → Yes/No
    # 새 방식:   "이 코드에서 어떻게 취약점이 생길 수 있는가?" → 가설(Hypothesis)
    #
    # Haiku는 싸고 빠르다 → 청크 전체를 배치로 훑어 가설만 뽑음
    # Sonnet은 비싸고 정확하다 → Haiku가 뽑은 가설만 깊게 검증

    def generate_hypotheses(
        self,
        chunks: list,
        readme_summary: str,
        batch_size: int = 6,
    ) -> list[VulnFinding]:
        """
        청크 배치 → Haiku → 보안 가설 목록.

        Haiku에게 "취약한가?"가 아니라
        "입력이 어느 경로로 흘러서 어떤 문제를 일으킬 수 있는가?" 를 묻는다.
        """
        all_findings: list[VulnFinding] = []
        total = len(chunks)

        for i in range(0, total, batch_size):
            batch      = chunks[i : i + batch_size]
            batch_text = "\n\n---\n\n".join(c.to_prompt() for c in batch)
            batch_num  = i // batch_size + 1
            total_batches = (total + batch_size - 1) // batch_size
            print(f"    Haiku 배치 {batch_num}/{total_batches} ({len(batch)}개 청크)...")

            prompt = f"""You are a security researcher.
Package: {readme_summary}

Below are {len(batch)} Python function chunks.
Each chunk includes: imports, class context (if method), callers, callees, and detected signals.

{batch_text}

Your task: For each chunk, form a SECURITY HYPOTHESIS.
A hypothesis answers: "IF an attacker controls [X], THEN [Y] could happen via [Z code path]."

Rules:
- Only generate hypotheses for chunks where attacker-controlled data can plausibly reach a dangerous operation.
- "plausibly" means: a realistic HTTP request, user-supplied file, or API call could trigger it.
- Be specific about WHICH variable carries the tainted data and WHERE it goes.
- Skip chunks that only process developer-controlled or internal data.
- Confidence reflects how certain you are the attack path is real and the impact is meaningful.

Respond with ONLY a JSON array ([] if no hypotheses):
[
  {{
    "vuln_type": "ReDoS",
    "confidence": 0.80,
    "affected_file": "multipart/multipart.py",
    "affected_line": 160,
    "description": "Content-Type header value is parsed by a regex with catastrophic backtracking",
    "root_cause": "The regex at line 160 has nested quantifiers; a crafted boundary string causes O(2^n) backtracking",
    "poc_sketch": "Send POST with Content-Type: multipart/form-data; boundary=<crafted 50-char string>"
  }}
]"""

            raw  = self._chat(HAIKU, prompt, max_tokens=2048)
            data = self._parse_json_list(raw)
            findings = [
                VulnFinding.model_validate(d)
                for d in data
                if d.get("confidence", 0) >= 0.5
            ]
            all_findings.extend(findings)

        return all_findings

    # ── 기존 트리아지 (하위 호환 유지) ──────────────────────────────────────

    def triage_chunks(self, chunks, readme_summary, batch_size=6):
        return self.generate_hypotheses(chunks, readme_summary, batch_size)

    # ── Stage 2b: 기존 키워드 기반 트리아지 (하위 호환) ─────────────────────

    def triage(self, suspicious_paths_text: str, readme_summary: str) -> list[VulnFinding]:
        """정적 분석 결과 → 실제 취약점 후보 선별. confidence < 0.5 제거."""
        prompt = f"""README summary: {readme_summary}

SUSPICIOUS CODE PATHS:
{suspicious_paths_text}

You are a security researcher. For each code path, assess whether it is a real, exploitable vulnerability.
Respond with ONLY a valid JSON array (empty [] if nothing exploitable):

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
        raw  = self._chat(HAIKU, prompt)
        data = self._parse_json_list(raw)
        return [VulnFinding.model_validate(d) for d in data if d.get("confidence", 0) >= 0.5]

    def triage_library(self, file_content: str, file_path: str,
                       package_name: str, readme_summary: str) -> list[VulnFinding]:
        """정적 분석이 아무것도 못 잡은 라이브러리용 — 파일 직접 분석."""
        prompt = f"""Package: {package_name}  File: {file_path}
README: {readme_summary}

=== SOURCE CODE ===
{file_content[:8000]}

This is a library (no explicit request.body patterns).
Find security vulnerabilities directly: logic bugs, resource exhaustion,
type confusion, path traversal, or any exploitable issue.

Respond with ONLY a valid JSON array (empty [] if nothing found):
[{{"vuln_type":"...", "confidence":0.0, "affected_file":"{file_path}",
   "affected_line":null, "description":"...", "root_cause":"...", "poc_sketch":"..."}}]"""
        raw  = self._chat(HAIKU, prompt)
        data = self._parse_json_list(raw)
        return [VulnFinding.model_validate(d) for d in data if d.get("confidence", 0) >= 0.5]

    # ── Stage 3a: Sonnet 심층 분석 + PoC ─────────────────────────────────────

    _REPORT_TOOL = {
        "name": "report_vulnerability",
        "description": "Report the vulnerability analysis result with PoC",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type":     {"type": "string"},
                "confidence":    {"type": "number"},
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

    def analyze(self, finding: VulnFinding, context: str,
                package_name: str) -> DeepAnalysis | None:
        """취약점 후보 → 전체 공격 경로 추적 + 실행 가능한 PoC 생성."""
        # Haiku가 생성한 poc_sketch를 Sonnet에 명시적으로 전달
        hypothesis_section = ""
        if finding.poc_sketch:
            hypothesis_section = f"""
Haiku's hypothesis (verify this):
  Attack vector: {finding.poc_sketch}
  Root cause: {finding.root_cause}

Your job: Verify if this hypothesis is correct by tracing the code.
If valid, write a PoC that proves it. If invalid (has mitigation), set confidence < 0.5.
"""

        prompt = f"""Package: {package_name}
Vulnerability type: {finding.vuln_type}
File: {finding.affected_file} (line {finding.affected_line})
Description: {finding.description}
{hypothesis_section}
=== SOURCE CODE (call chain context) ===
{context}

Tasks:
1. Verify the hypothesis above by tracing the exact code path.
2. Check for any sanitization, validation, or bounds checks that would block the attack.
3. If exploitable: write a STANDALONE PoC (no web server, import library directly).
   Print exactly: VULNERABLE: <evidence>
4. If NOT exploitable (has mitigation): set confidence < 0.5, explain the mitigation.
5. Call report_vulnerability."""

        resp = self._client.messages.create(
            model=SONNET,
            max_tokens=4096,
            system=[{"type": "text", "text": self._system,
                     "cache_control": {"type": "ephemeral"}}],
            tools=[self._REPORT_TOOL],
            tool_choice={"type": "any"},
            messages=[{"role": "user", "content": [
                {"type": "text", "text": prompt, "cache_control": {"type": "ephemeral"}}
            ]}],
        )

        for block in resp.content:
            if block.type == "tool_use" and block.name == "report_vulnerability":
                data = block.input
                conf = float(data.get("confidence", 0))
                desc = data.get("description", "")[:120]
                root = data.get("root_cause", "")[:120]
                print(f"    [Sonnet] conf={conf:.2f}  {desc}")
                if conf < 0.4:
                    print(f"    [Sonnet] 기각 이유: {root}")
                    return None
                try:
                    return DeepAnalysis(**data)
                except Exception as e:
                    print(f"    [Sonnet] 모델 생성 실패: {e}")
                    return None
        print("    [Sonnet] tool_use 블록 없음 — 텍스트 응답:")
        for block in resp.content:
            if hasattr(block, "text"):
                print(f"    {block.text[:300]}")
        return None

    # ── Stage 3c: DA 리뷰 ────────────────────────────────────────────────────

    def da_review(self, analysis: DeepAnalysis, context: str,
                  package_name: str) -> DAResult:
        """PoC 실행 불가 케이스의 최종 검토. 중립적으로 실제 공격 가능성 판단."""
        prompt = f"""You are reviewing a vulnerability report for {package_name}.

Vulnerability: {analysis.vuln_type}
Description:   {analysis.description}
Root cause:    {analysis.root_cause}
CVSS Score:    {analysis.cvss_score}

PoC:
```python
{analysis.poc_code}
```

Relevant source:
{context[:3000]}

Review objectively:
1. Is the PoC valid and would it work as written?
2. Is there a real attack path from external (attacker-controlled) input to the sink?
3. Are there existing mitigations (auth, sandboxing, version conditions)?
4. Is this already a known/patched issue?

Rules:
- da_survived=true  if PoC is valid AND attack path exists AND no effective mitigation
- da_survived=false if PoC is broken OR attack path is blocked OR already patched
- Do NOT reject only because specific conditions are required — most real CVEs have conditions.

Respond with ONLY:
{{"da_survived": true, "rebuttal": "brief reason", "final_confidence": 0.0}}"""

        raw = self._chat(SONNET, prompt, max_tokens=1024)
        try:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            return DAResult(**json.loads(m.group(0))) if m else DAResult(
                da_survived=True, rebuttal="parse error", final_confidence=analysis.confidence
            )
        except Exception:
            return DAResult(da_survived=True, rebuttal="parse error",
                            final_confidence=analysis.confidence)

    # ── README 요약 ───────────────────────────────────────────────────────────

    def summarize_readme(self, readme_text: str) -> str:
        prompt = (
            "Security researcher perspective: summarize this package's attack surface "
            "in 3-5 lines. Focus on: networking, external input handling, file I/O, "
            f"serialization.\n\nREADME:\n{readme_text[:3000]}"
        )
        resp = self._client.messages.create(
            model=HAIKU,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()
