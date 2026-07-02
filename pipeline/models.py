"""
파이프라인 전체에서 공유하는 데이터 모델.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pydantic import BaseModel


# ── Stage 1 출력 ──────────────────────────────────────────────────────────────

@dataclass
class SuspiciousPath:
    file: str
    vuln_type: str
    sink_name: str
    sink_line: int
    source_hint: str
    code_snippet: str
    function_name: str = ""


@dataclass
class StaticResult:
    file: str
    suspicious_paths: list[SuspiciousPath] = field(default_factory=list)


# ── Stage 2 출력 (Haiku 트리아지) ────────────────────────────────────────────

class VulnFinding(BaseModel):
    vuln_type: str
    confidence: float
    affected_file: str
    affected_line: int | None = None
    description: str
    root_cause: str
    poc_sketch: str | None = ""

    model_config = {"populate_by_name": True}

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if isinstance(obj, dict) and isinstance(obj.get("affected_line"), str):
            m = re.search(r"\d+", obj["affected_line"])
            obj["affected_line"] = int(m.group()) if m else None
        return super().model_validate(obj, **kwargs)


# ── Stage 3a 출력 (Sonnet 심층 분석) ─────────────────────────────────────────

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


# ── Stage 3b 출력 (PoC 실행) ─────────────────────────────────────────────────

@dataclass
class PoCResult:
    executed: bool
    vulnerable: bool
    stdout: str
    stderr: str
    exit_code: int
    evidence: str
    error_msg: str = ""


# ── Stage 3c 출력 (DA 리뷰) ───────────────────────────────────────────────────

class DAResult(BaseModel):
    da_survived: bool
    rebuttal: str
    final_confidence: float
