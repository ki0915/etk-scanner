"""
report_gen.py — 증명 가능한 리포트 자동 생성 (Stage 6)

악용성 게이트를 통과한 발견에 대해:
  1. exploit PoC를 실제로 다시 실행해 출력을 박제 (증명 가능성)
  2. 표준 라이브러리/스펙과의 대조 결과 포함
  3. CVSS, CWE, 영향, 완화책, DA 반박까지 포함한 마크다운 리포트 생성

리포트는 PoC 출력이 실제 실행 결과임을 보장한다 (재현 불가능한 주장 금지).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pipeline.agent_tools import ToolBox


def _dup_section(finding: dict) -> str:
    """중복 체크 결과를 마크다운으로."""
    dc = finding.get("dup_check")
    if not dc:
        return "(중복 체크 미실행)"
    lines = []
    if dc.get("is_duplicate"):
        lines.append(f"⚠️ **중복 가능성**: {dc.get('matching_known_id','?')} 와 동일 추정")
    else:
        lines.append(f"신규 가능성 신뢰도: {dc.get('novelty_confidence','?')}")
    lines.append(f"타 채널 기지(advisory/docs) 의심: {dc.get('likely_known_elsewhere','?')}")
    lines.append(f"판단: {dc.get('reasoning','')}")
    known = dc.get("osv_known", [])
    if known:
        lines.append(f"\nOSV 등록 (참고, 무관할 수 있음):")
        for k in known[:5]:
            lines.append(f"- {k.get('id','')}: {k.get('summary','')[:70]}")
    queries = dc.get("search_queries", [])
    if queries:
        lines.append(f"\n**신고 전 직접 검색 권장:**")
        for q in queries:
            lines.append(f"- `{q}`")
    return "\n".join(lines)


def _rerun_poc(toolbox: ToolBox, poc_code: str) -> tuple[bool, str]:
    """
    리포트에 박을 PoC를 실제로 실행. (성공여부, 출력)

    '성공'의 정의: PoC가 정상 실행되어(EXIT=0) 보안 영향을 보여주는 출력을 냄.
    PoC마다 출력 컨벤션이 다르므로(VULNERABLE / ALLOWED / 비교결과 등),
    "정상 종료 + 명시적 실패신호 없음"을 재현 성공으로 본다.
    """
    if not poc_code or not poc_code.strip():
        return False, "(no PoC code)"
    output = toolbox.run_poc(poc_code)
    # 실행 자체 실패 신호
    failed = any(s in output for s in (
        "NOT_REPRODUCED", "TIMEOUT", "SYNTAX_ERROR", "REJECTED:", "BLOCKED:",
        "Traceback", "ImportError", "ModuleNotFound",
    ))
    ran_ok = output.startswith("EXIT=0") or "EXIT=0" in output[:10]
    reproduced = ran_ok and not failed
    return reproduced, output


def generate_report(
    finding: dict,
    toolbox: ToolBox,
    package: str,
    repo_path: str,
    out_dir: Path,
) -> Path | None:
    seed = finding.get("_seed", {})
    gate = finding.get("exploit_gate", {})
    func_name = seed.get("entry_name", "unknown")

    # exploit PoC 실제 재실행 (증명)
    poc_code = gate.get("exploit_poc", "") or finding.get("poc_code", "")
    reproduced, poc_output = _rerun_poc(toolbox, poc_code)

    verified_mark = "✅ 재현 확인됨" if reproduced else "⚠️ 재현 실패 (리포트 보류 권장)"

    severity = gate.get("severity", "unknown")
    cwe = gate.get("cwe", finding.get("vuln_class", "?"))

    md = f"""# [후보] {package}: {func_name} — {cwe}

| 항목 | 내용 |
|------|------|
| 작성 시각 | {datetime.now().strftime('%Y-%m-%d %H:%M')} |
| 패키지 | {package} |
| 대상 함수 | `{func_name}` |
| 심각도 (추정) | {severity} |
| CWE | {cwe} |
| 재현 상태 | {verified_mark} |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) |

---

## 보안 의도 (Security Intent)

{finding.get('security_intent', gate.get('security_boundary', '?'))}

## 취약점 요약

{gate.get('rebuttal_answer') or gate.get('security_boundary') or finding.get('reasoning', '?')}

## 보안 경계 위반

{gate.get('security_boundary', '?')}

## 현실적 악용 시나리오

{gate.get('consumer_scenario', '?')}

## 공격 벡터

{finding.get('attack_vector', '?')}

---

## 검증된 PoC (실제 실행 출력)

아래 PoC는 리포트 생성 시점에 **실제로 실행되어** 출력이 박제되었습니다.

```python
{poc_code}
```

**실행 출력:**
```
{poc_output.strip()}
```

---

## Devil's Advocate (메인테이너 반박 대비)

**예상 반박:** {gate.get('maintainer_rebuttal', '?')}

**반론:** {gate.get('rebuttal_answer', '?')}

---

## 중복/기지 체크 (자동)

{_dup_section(finding)}

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색
- [ ] 최신 버전에서도 재현되는지 확인 (이 리포트는 클론된 버전 기준)
- [ ] 위 '악용 시나리오'가 실제 사용 패턴인지 재확인
- [ ] 메인테이너 반박이 반론으로 막히는지 최종 판단
- [ ] CVSS 점수는 메인테이너 판단에 맡기는 톤으로 작성

## 참고

- 대상 소스: `{repo_path}`
- 자동 판정 신뢰도: {gate.get('confidence', '?')}
"""

    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = func_name.strip("_").replace(".", "_")
    out_path = out_dir / f"{package}-{safe_name}-candidate.md"
    out_path.write_text(md, encoding="utf-8")
    return out_path


def generate_all_reports(
    reportable: list[dict],
    toolbox: ToolBox,
    package: str,
    repo_path: str,
    out_dir: Path,
) -> list[Path]:
    paths = []
    print(f"\n  [리포트 생성] {len(reportable)}개")
    for finding in reportable:
        p = generate_report(finding, toolbox, package, repo_path, out_dir)
        if p:
            print(f"    -> {p.name}")
            paths.append(p)
    return paths
