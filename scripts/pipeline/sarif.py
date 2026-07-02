"""
sarif.py — findings → SARIF 2.1.0 변환

SARIF는 GitHub Security 탭 / CI가 읽는 표준 정적분석 출력 포맷.
정적 모드(무료)든 LLM 모드든 동일 SARIF로 출력해 CI에 통합.
"""

from __future__ import annotations

import json
from pathlib import Path

_TOOL_NAME = "ETK-Scanner"
_TOOL_URI = "https://github.com/"   # 프로젝트 repo로 교체
_VERSION = "0.1.0"

# 심각도 → SARIF level
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "warning",
    "none": "note",
}


def _rule_id(finding: dict) -> str:
    cwe = finding.get("cwe") or finding.get("vuln_class") or "SEC"
    # "CWE-918 SSRF" → "CWE-918"
    return str(cwe).split()[0].replace(":", "")


def finding_to_result(finding: dict, repo_root: str) -> dict:
    seed = finding.get("_seed", finding)
    fpath = seed.get("file", finding.get("file", "unknown"))
    # repo 루트 기준 상대경로
    try:
        rel = str(Path(fpath).resolve().relative_to(Path(repo_root).resolve()))
    except (ValueError, OSError):
        rel = fpath
    rel = rel.replace("\\", "/")
    line = int(seed.get("start_line", finding.get("start_line", 1)) or 1)

    severity = (finding.get("security_filter", {}) or {}).get(
        "severity", finding.get("severity", "unknown"))
    level = _LEVEL.get(str(severity).lower(), "warning")

    msg = (finding.get("reasoning")
           or finding.get("suspected_bypass")
           or finding.get("security_intent")
           or seed.get("entry_name", "security finding"))

    return {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": f"[{seed.get('entry_name','?')}] {msg}"[:1000]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": rel},
                "region": {"startLine": max(1, line)},
            }
        }],
        "properties": {
            "severity": severity,
            "cwe": finding.get("cwe", finding.get("vuln_class", "")),
            "confidence": finding.get("confidence", ""),
            "stage": finding.get("_stage", ""),
        },
    }


def build_sarif(findings: list[dict], repo_root: str) -> dict:
    results = [finding_to_result(f, repo_root) for f in findings]
    # 룰 목록 (중복 제거)
    rules = {}
    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": str(f.get("cwe", f.get("vuln_class", rid)))},
            }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": _VERSION,
                    "informationUri": _TOOL_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(findings: list[dict], repo_root: str, out_path: str | Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(build_sarif(findings, repo_root), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path
