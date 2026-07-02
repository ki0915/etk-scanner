"""
agent_runner.py — 탐색형 에이전트 파이프라인 실행기

정적 그래프(지도) → 불일치 seed 생성 → 에이전트가 능동 탐색하며 판정.
미지의 취약점 발견을 목표로 한다.

Usage:
  python scripts/agent_runner.py ETK-CAND-0002 xmltodict
  python scripts/agent_runner.py ETK-CAND-0002 xmltodict --repo <path>
  python scripts/agent_runner.py ETK-CAND-0002 xmltodict --max-seeds 10
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
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def _load_dotenv() -> None:
    import os
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv()

from pipeline.provider import Provider, BudgetExceededError
from pipeline.graph_builder import build_graph
from pipeline.differential import find_differential_candidates
from pipeline.static_filter import run_static_filter
from pipeline.intent_finder import build_intent_seeds
from pipeline.screen_single import screen_candidates
from pipeline.agent import investigate, _record_fp
from pipeline.security_filter import filter_security
from pipeline.dup_check import run_dup_check
from pipeline.agent_tools import ToolBox
from pipeline.report_gen import generate_all_reports


def _auto_repo(candidate_id: str) -> Path:
    base = Path(__file__).parent.parent / "candidates"
    matches = sorted(base.glob(f"{candidate_id}*"))
    if not matches:
        raise FileNotFoundError(f"후보 폴더 없음: {candidate_id}")
    return matches[0] / "repo"


def _build_seeds(repo_path: Path, db_path: Path, max_seeds: int) -> list[dict]:
    """
    seed 생성 전략 (분류 기준 전환):
      1순위: 보안 의도 함수 (intent) — 로직 버그/우회를 잡는 핵심
      2순위: 불일치(differential) — 권한 누락류
      3순위: 정적 싱크 경로 — 명백한 injection류

    intent를 1순위로 두는 이유: 미지의 CVE 대부분이 싱크 없는 로직 버그라,
    "보안 판단 함수"를 직접 조사해야 발견 가능.
    """
    seeds = []
    seen = set()

    def _add(s):
        key = s.get("entry_name", "")
        if key and key not in seen:
            seen.add(key)
            seeds.append(s)

    # 1순위: 보안 의도 함수
    for s in build_intent_seeds(repo_path, max_seeds=max_seeds * 2):
        _add(s)

    # 2순위: 불일치 (권한 누락)
    for c in find_differential_candidates(db_path):
        _add({
            "entry_name": c.entry_name, "sink_name": c.sink_name,
            "sink_kind": c.sink_kind, "path": c.path,
            "missing_guards": c.missing_guards, "sibling_entry": c.sibling_entry,
            "asymmetry_score": c.asymmetry_score(), "source": "differential",
        })

    # intent 점수 우선 정렬 (intent는 score, 나머지는 0)
    seeds.sort(key=lambda s: s.get("score", 0), reverse=True)
    return seeds[:max_seeds]


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Pentester - Agent Mode")
    parser.add_argument("candidate_id")
    parser.add_argument("package_name")
    parser.add_argument("--repo", default=None)
    parser.add_argument("--max-seeds", type=int, default=40,
                        help="단일턴 분류 대상 의도함수 수 (싸므로 넉넉히)")
    parser.add_argument("--verify-top", type=int, default=5,
                        help="멀티턴 PoC 검증할 상위 후보 수 (비싸므로 소수)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    repo_path = Path(args.repo) if args.repo else _auto_repo(args.candidate_id)
    data_dir = Path(__file__).parent.parent / "data" / args.candidate_id
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "graph.db"
    metrics_path = data_dir / "agent_metrics.json"

    start = datetime.now()
    print(f"\n{'='*60}")
    print(f"  AI Pentester - 탐색 에이전트 모드")
    print(f"  {args.candidate_id} | {args.package_name}")
    print(f"  레포: {repo_path}")
    print(f"{'='*60}")

    # ── Stage 0: 그래프 (지도) ────────────────────────────────────────────
    print(f"\n[1/4 지도] 콜그래프 구축")
    build_graph(repo_path, db_path)

    # ── Stage 1: 의도 함수 추출 (정적, 무료) ──────────────────────────────
    print(f"\n[2/4 후보] 보안 의도 함수 추출 (정적)")
    seeds = build_intent_seeds(repo_path, max_seeds=args.max_seeds)
    print(f"  의도 함수 {len(seeds)}개")

    provider = Provider(metrics_path=metrics_path, stage="screen")
    toolbox = ToolBox(db_path, repo_path, args.package_name)

    # ── Stage 2: 단일턴 분류 (Haiku, 싸게) ────────────────────────────────
    print(f"\n[3/4 분류] 단일턴 가설 생성 (Haiku, 도구 없음)")
    survivors = []
    try:
        survivors = screen_candidates(seeds, provider, verbose=not args.quiet)
    except BudgetExceededError as e:
        print(f"\n[예산 초과] 분류 중단: {e}")

    # 상위 N개만 멀티턴 검증 (비용 통제)
    to_verify = survivors[:args.verify_top]

    # ── Stage 3: 멀티턴 PoC 검증 (소수만) ─────────────────────────────────
    print(f"\n[4/4 검증] 멀티턴 PoC 검증 — 상위 {len(to_verify)}개 (전체 {len(survivors)})")
    confirmed = []
    provider.stage = "verify"
    for i, hyp in enumerate(to_verify, 1):
        seed = hyp["_seed"]
        # 분류 가설을 seed에 주입 (검증 에이전트가 활용)
        seed = {**seed,
                "suspected_bypass": hyp.get("suspected_bypass", ""),
                "why_stdlib_disagrees": hyp.get("why_stdlib_disagrees", ""),
                "screen_vuln_class": hyp.get("vuln_class", "")}
        print(f"    [{i}/{len(to_verify)}] {seed.get('entry_name','?')} "
              f"(분류신뢰도 {hyp.get('confidence')})")
        try:
            verdict = investigate(seed, toolbox, provider, data_dir,
                                  model="claude-sonnet-4-6", verbose=not args.quiet,
                                  package=args.package_name, max_turns=12)
        except BudgetExceededError as e:
            print(f"\n[예산 초과] 검증 중단: {e}")
            break
        verdict["_seed"] = seed
        if verdict.get("verdict") == "confirmed":
            confirmed.append(verdict)
        elif verdict.get("verdict") == "not_vulnerable":
            _record_fp(data_dir,
                       pattern=f"{seed.get('entry_name','')}",
                       lesson=verdict.get("reasoning", "")[:200])

    # ── Stage 4: 보안영향 필터 (기능버그 vs 취약점, 단일턴) ───────────────
    reportable = []
    if confirmed:
        provider.stage = "security_filter"
        try:
            reportable = filter_security(confirmed, provider, verbose=not args.quiet)
        except BudgetExceededError as e:
            print(f"\n[예산 초과] 필터 중단: {e}")
            reportable = confirmed   # 필터 못 돌리면 일단 전부 surfacing

    # ── Stage 4.5: 중복/기지 체크 (OSV + LLM) ─────────────────────────────
    novel = reportable
    if reportable:
        provider.stage = "dup_check"
        try:
            novel = run_dup_check(reportable, args.package_name, provider,
                                  verbose=not args.quiet)
        except BudgetExceededError as e:
            print(f"\n[예산 초과] 중복체크 중단: {e}")

    # ── Stage 5: 리포트 생성 (신규 보안 취약점만) ─────────────────────────
    report_paths = []
    reportable = novel
    if reportable:
        report_dir = Path(__file__).parent.parent / "reports" / "candidates" / args.candidate_id
        for c in reportable:
            sf = c.get("security_filter", {})
            c["exploit_gate"] = {
                "reportable": True,
                "severity": sf.get("severity", "unknown"),
                "cwe": c.get("vuln_class", c.get("screen_vuln_class", "?")),
                "security_boundary": sf.get("security_boundary", c.get("security_intent", "")),
                "consumer_scenario": c.get("attack_vector", ""),
                "maintainer_rebuttal": "",
                "rebuttal_answer": c.get("reasoning", ""),
                "exploit_poc": c.get("poc_code", ""),
                "confidence": sf.get("confidence", c.get("confidence", 0)),
            }
        report_paths = generate_all_reports(
            reportable, toolbox, args.package_name, str(repo_path), report_dir,
        )

    # ── 최종 요약 ─────────────────────────────────────────────────────────
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n{'='*60}")
    print(f"  최종 리포트")
    print(f"{'='*60}")
    print(f"  {provider.summary()}")
    print(f"  소요: {elapsed:.0f}초")
    print(f"\n  의도함수 {len(seeds)} → 분류통과 {len(survivors)} "
          f"→ 검증 {len(to_verify)} → 확정버그 {len(confirmed)} → 보안취약점 {len(reportable)}")
    print(f"  생성된 리포트: {len(report_paths)}개")
    for c in reportable:
        sf = c.get("security_filter", {})
        print(f"    [{sf.get('severity','?')}] {c.get('_seed',{}).get('entry_name','?')} "
              f"- {sf.get('attacker_gain','')[:50]}")
    for p in report_paths:
        print(f"    리포트: {p}")


if __name__ == "__main__":
    main()
