"""
Data models for the AI pentesting pipeline.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    RCE = "Remote Code Execution"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Insecure Deserialization"
    SSRF = "SSRF"
    XXE = "XXE"
    RACE_CONDITION = "Race Condition"
    AUTH_BYPASS = "Authentication Bypass"
    SYMLINK = "Symlink Following"
    REDOS = "ReDoS"
    MEMORY = "Memory Safety"
    DOS = "Denial of Service"
    OTHER = "Other"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class CodeChunk:
    """A semantic unit of source code — function, class, or module-level block."""
    file_path: str
    chunk_type: str          # "function" | "class" | "method" | "module"
    name: str
    code: str
    start_line: int
    end_line: int
    context: str = ""        # surrounding imports / class header for methods
    language: str = "python"

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.start_line}-{self.end_line}"

    def to_prompt_block(self) -> str:
        return (
            f"# File: {self.file_path} (lines {self.start_line}–{self.end_line})\n"
            f"# Type: {self.chunk_type} `{self.name}`\n\n"
            + (f"# Context:\n{self.context}\n\n" if self.context else "")
            + f"```{self.language}\n{self.code}\n```"
        )


@dataclass
class VulnHypothesis:
    """A potential vulnerability flagged by the screener (cheap model)."""
    chunk: CodeChunk
    vuln_type: str
    description: str
    confidence: float        # 0–10; only >= SCREEN_THRESHOLD forwarded to validator
    location_hint: str       # "line 42" or function name
    reasoning: str
    screener_model: str = ""

    @property
    def is_high_confidence(self) -> bool:
        threshold = float(os.getenv("SCREEN_THRESHOLD", "6.0"))
        return self.confidence >= threshold


@dataclass
class ValidationResult:
    """Deep analysis result produced by the validator (expensive model)."""
    hypothesis: VulnHypothesis

    # Verdict
    confirmed: bool
    severity: Severity
    cvss_score: float

    # Analysis
    attack_path: str
    poc_code: str
    da_rebuttal: str         # Devil's Advocate: reasons it might NOT be a vuln
    da_response: str         # Response to the rebuttal

    # Meta
    mitigation: str
    validator_model: str = ""
    raw_response: str = ""

    def to_markdown(self) -> str:
        status = "CONFIRMED" if self.confirmed else "FALSE POSITIVE"
        return f"""## [{status}] {self.hypothesis.vuln_type} — {self.hypothesis.chunk.location}

**Confidence (screener):** {self.hypothesis.confidence}/10
**CVSS:** {self.cvss_score} ({self.severity.value})

### Description
{self.hypothesis.description}

### Attack Path
{self.attack_path}

### PoC
```python
{self.poc_code}
```

### Devil's Advocate
**Rebuttal:** {self.da_rebuttal}
**Response:** {self.da_response}

### Mitigation
{self.mitigation}
"""


@dataclass
class PipelineReport:
    """Aggregated output of one full pipeline run."""
    candidate_id: str
    package_name: str
    repo_path: str
    total_chunks: int
    screened_count: int      # chunks with >= 1 hypothesis above threshold
    confirmed_count: int
    results: list[ValidationResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Package : {self.package_name}",
            f"Chunks  : {self.total_chunks}",
            f"Screened: {self.screened_count} (above confidence threshold)",
            f"Confirmed: {self.confirmed_count} vulnerabilities",
            "",
        ]
        for r in self.results:
            if r.confirmed:
                lines.append(f"  [{r.severity.value}] {r.hypothesis.vuln_type}")
                lines.append(f"    {r.hypothesis.chunk.location}")
                lines.append(f"    CVSS {r.cvss_score}")
                lines.append("")
        return "\n".join(lines)
