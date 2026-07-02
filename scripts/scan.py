"""
scan.py — DevSecOps CI 보안 스캔 진입점

비용 인식 설계:
  - 기본(--mode static): LLM 없이 정적 탐지만. 무료. CI 매 PR에 부담 없음.
  - --mode llm: 정적 후보를 저가 LLM 단일턴 분류로 정제. 예산 상한 적용.
  - --mode full: LLM 분류 + 멀티턴 PoC 검증 (비쌈, 수동 실행 권장).

출력:
  - SARIF (GitHub Security 탭)
  - cost.json (단계별 비용 — "비용 인식"의 증거)
  - exit code: 심각도 임계 초과 시 non-zero (CI 게이트)

Usage:
  python scripts/scan.py <repo_path> --mode static
  python scripts/scan.py <repo_path> --mode llm --package <name> --budget 1000
  python scripts/scan.py <repo_path> --fail-on high
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from pipeline.intent_finder import find_intent_functions
from pipeline.sarif import write_sarif

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1, "none": 0}


def _load_dotenv() -> None:
    import os
    env = Path(__file__).parent.parent / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def scan_static(repo_path: Path) -> list[dict]:
    """무료 정적 티어: 보안 의도 함수 탐지 (LLM 0). 언어 자동 감지."""
    from pipeline.intent_finder_multi import detect_language, find_intent_js
    lang = detect_language(repo_path)
    if lang == "js":
        js_funcs = find_intent_js(repo_path)
        findings = []
        for f in js_funcs:
            sev = "high" if f.score >= 8 else ("medium" if f.score >= 5 else "low")
            findings.append({
                "_seed": {"entry_name": f.name, "file": f.file, "start_line": f.start_line},
                "vuln_class": "security-decision (JS/TS)",
                "cwe": "CWE-798" if "hardcoded_secret" in str(f.signals) else "CWE-710",
                "severity": sev,
                "reasoning": f"Security-relevant code (signals: {', '.join(f.signals[:3])}). "
                             f"(static tier — no LLM confirmation)",
                "confidence": round(min(f.score / 10, 0.95), 2),
                "_stage": "static-js", "file": f.file, "start_line": f.start_line,
            })
        return findings

    funcs = find_intent_functions(repo_path)
    findings = []
    for f in funcs:
        # 정적 신호 강도로 심각도 근사 (LLM 없이)
        sev = "medium" if f.score >= 6 else ("low" if f.score >= 4 else "none")
        findings.append({
            "_seed": {"entry_name": f.name, "file": f.file, "start_line": f.start_line},
            "vuln_class": "security-decision-function",
            "cwe": "CWE-710",
            "severity": sev,
            "reasoning": f"Security-decision function (signals: {', '.join(f.signals[:3])}). "
                         f"Review for logic-bug / bypass. (static tier — no LLM confirmation)",
            "confidence": round(min(f.score / 10, 0.9), 2),
            "_stage": "static",
            "file": f.file,
            "start_line": f.start_line,
        })
    return findings


def scan_llm(repo_path: Path, package: str, budget_krw: int, verbose: bool) -> list[dict]:
    """LLM 티어: 정적 후보 → 단일턴 분류로 정제 (예산 상한)."""
    from pipeline.provider import Provider
    from pipeline.screen_single import screen_candidates
    from pipeline.intent_finder import build_intent_seeds

    # 예산 임시 오버라이드
    import os
    prov = Provider(stage="scan_screen")
    prov._budget["total_budget_krw"] = budget_krw

    seeds = build_intent_seeds(repo_path, max_seeds=40)
    survivors = screen_candidates(seeds, prov, verbose=verbose)
    findings = []
    for s in survivors:
        seed = s["_seed"]
        findings.append({
            "_seed": {"entry_name": seed["entry_name"], "file": seed.get("file"),
                      "start_line": seed.get("start_line", 1)},
            "vuln_class": s.get("vuln_class", "?"),
            "cwe": s.get("vuln_class", "CWE-710"),
            "severity": "medium" if s.get("confidence", 0) >= 0.7 else "low",
            "reasoning": s.get("suspected_bypass", ""),
            "confidence": s.get("confidence", 0),
            "_stage": "llm-screen",
            "file": seed.get("file"),
            "start_line": seed.get("start_line", 1),
        })
    return findings, prov


def main() -> None:
    ap = argparse.ArgumentParser(description="ETK DevSecOps 보안 스캔")
    ap.add_argument("repo", help="스캔할 repo 경로")
    ap.add_argument("--mode", choices=["static", "llm"], default="static",
                    help="static=무료(LLM 없음), llm=단일턴 분류(예산 상한)")
    ap.add_argument("--package", default="", help="LLM 모드 시 패키지명")
    ap.add_argument("--budget", type=int, default=1000, help="LLM 모드 예산(원)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                    default="never", help="이 심각도 이상 발견 시 exit 1 (CI 게이트)")
    ap.add_argument("--sarif", default="results.sarif", help="SARIF 출력 경로")
    ap.add_argument("--cost", default="cost.json", help="비용 리포트 경로")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    _load_dotenv()
    repo = Path(args.repo)
    if not repo.exists():
        print(f"[error] repo 없음: {repo}", file=sys.stderr)
        sys.exit(2)

    start = datetime.now()
    print(f"[ETK-Scan] {repo} | mode={args.mode}")

    cost_krw = 0.0
    if args.mode == "static":
        findings = scan_static(repo)
    else:
        findings, prov = scan_llm(repo, args.package, args.budget, not args.quiet)
        cost_krw = prov._metrics.total_cost_krw

    # SARIF 출력
    write_sarif(findings, str(repo), args.sarif)

    # 비용 리포트 (비용 인식의 증거)
    elapsed = (datetime.now() - start).total_seconds()
    cost_report = {
        "mode": args.mode,
        "findings": len(findings),
        "cost_krw": round(cost_krw, 2),
        "elapsed_sec": round(elapsed, 1),
        "cost_per_finding_krw": round(cost_krw / len(findings), 2) if findings else 0,
    }
    Path(args.cost).write_text(json.dumps(cost_report, indent=2, ensure_ascii=False),
                               encoding="utf-8")

    # 요약
    by_sev = {}
    for f in findings:
        s = f.get("severity", "unknown")
        by_sev[s] = by_sev.get(s, 0) + 1
    print(f"[결과] {len(findings)}건 | {by_sev} | 비용 {cost_krw:.0f}원 | {elapsed:.1f}초")
    print(f"[출력] SARIF={args.sarif} cost={args.cost}")

    # CI 게이트: fail-on 심각도 이상이면 exit 1
    if args.fail_on != "never":
        threshold = _SEV_ORDER[args.fail_on]
        worst = max((_SEV_ORDER.get(f.get("severity", "none"), 0) for f in findings),
                    default=0)
        if worst >= threshold:
            print(f"[게이트] {args.fail_on} 이상 발견 → CI 실패")
            sys.exit(1)
    print("[게이트] 통과")


if __name__ == "__main__":
    main()
