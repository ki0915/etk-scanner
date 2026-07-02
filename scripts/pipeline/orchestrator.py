"""
Orchestrator — ties together chunker → screener → validator.

Flow:
  1. chunk_repo()           → list[CodeChunk]
  2. screen_chunks()        → list[VulnHypothesis]  (cheap model, all chunks)
  3. filter by confidence   → only >= SCREEN_THRESHOLD forwarded
  4. validate_hypotheses()  → list[ValidationResult] (expensive model)
  5. emit PipelineReport
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pipeline.chunker import chunk_repo
from pipeline.models import PipelineReport, Severity
from pipeline.screener import SCREEN_THRESHOLD, screen_chunks
from pipeline.validator import validate_hypotheses
from pipeline.surface import scan_attack_surface
from pipeline.callgraph import build_callgraph
from pipeline.pathfinder import find_paths, deduplicate_paths

# Re-export so models.py can import from here without circular issues
__all__ = ["SCREEN_THRESHOLD", "run_pipeline"]


def run_pipeline_taint(
    candidate_id: str,
    package_name: str,
    repo_path: str | Path,
    *,
    api_key: Optional[str] = None,
    screen_only: bool = False,
    verbose: bool = True,
) -> PipelineReport:
    """
    테인트 기반 파이프라인 (신규).
    소스 → 싱크 경로를 먼저 찾고, 그 경로만 스크리닝합니다.
    """
    repo = Path(repo_path)

    # ── Stage 1: 공격 표면 식별 ───────────────────────────────────────────
    if verbose:
        print(f"\n[1/4] 소스/싱크 탐지 중 ({repo}) ...")
    sources, sinks = scan_attack_surface(repo)
    if verbose:
        print(f"      소스: {len(sources)}개 | 싱크: {len(sinks)}개")

    if not sources or not sinks:
        if verbose:
            print("      소스 또는 싱크 없음 — 종료")
        return PipelineReport(
            candidate_id=candidate_id, package_name=package_name,
            repo_path=str(repo), total_chunks=0, screened_count=0, confirmed_count=0,
        )

    # ── Stage 2: 콜 그래프 빌드 ──────────────────────────────────────────
    if verbose:
        print(f"\n[2/4] 콜 그래프 빌드 중 ...")
    cg = build_callgraph(repo)
    if verbose:
        print(f"      함수 {len(cg.nodes)}개, 엣지 {sum(len(v) for v in cg.edges.values())}개")

    # ── Stage 3: 소스→싱크 경로 탐색 ─────────────────────────────────────
    if verbose:
        print(f"\n[3/4] 소스→싱크 경로 탐색 중 ...")
    paths = find_paths(sources, sinks, cg)
    paths = deduplicate_paths(paths)
    if verbose:
        print(f"      경로 {len(paths)}개 발견 (중복 제거 후)")
        for p in paths:
            print(f"      [{p.source.kind}→{p.sink.kind}] {' → '.join(p.path)}")

    if not paths:
        return PipelineReport(
            candidate_id=candidate_id, package_name=package_name,
            repo_path=str(repo), total_chunks=len(sources)+len(sinks),
            screened_count=0, confirmed_count=0,
        )

    # ── Stage 4: 경로별 스크리닝 (Haiku) ─────────────────────────────────
    if verbose:
        print(f"\n[4/4] {len(paths)}개 경로 스크리닝 중 ...")
    candidates = screen_chunks(paths, api_key=api_key, verbose=verbose)

    if screen_only or not candidates:
        return PipelineReport(
            candidate_id=candidate_id, package_name=package_name,
            repo_path=str(repo), total_chunks=len(paths),
            screened_count=len(candidates), confirmed_count=0,
        )

    # ── Stage 5: 검증 (Sonnet) ───────────────────────────────────────────
    results = validate_hypotheses(candidates, api_key=api_key, verbose=verbose)
    confirmed = [r for r in results if r.confirmed]

    return PipelineReport(
        candidate_id=candidate_id, package_name=package_name,
        repo_path=str(repo), total_chunks=len(paths),
        screened_count=len(candidates), confirmed_count=len(confirmed),
        results=confirmed,
    )


def run_pipeline(
    candidate_id: str,
    package_name: str,
    repo_path: str | Path,
    *,
    api_key: Optional[str] = None,
    screen_only: bool = False,
    min_severity: Severity = Severity.LOW,
    verbose: bool = True,
) -> PipelineReport:
    """
    Run the full 3-stage pipeline on a cloned repository.

    Args:
        candidate_id:  ETK-CAND-XXXX identifier
        package_name:  Human-readable package name
        repo_path:     Path to the cloned repository root
        api_key:       Anthropic API key (falls back to ANTHROPIC_API_KEY env)
        screen_only:   Stop after screening, skip deep validation
        min_severity:  Only include results at or above this severity in report
        verbose:       Print progress to stdout
    """
    repo = Path(repo_path)

    # ── Stage 1: Chunk ────────────────────────────────────────────────────────
    if verbose:
        print(f"\n[1/3] Chunking {repo} ...")
    chunks = chunk_repo(repo)
    if verbose:
        print(f"      {len(chunks)} chunks extracted")

    if not chunks:
        return PipelineReport(
            candidate_id=candidate_id,
            package_name=package_name,
            repo_path=str(repo),
            total_chunks=0,
            screened_count=0,
            confirmed_count=0,
        )

    # ── Stage 2: Screen (cheap model) ─────────────────────────────────────────
    if verbose:
        print(f"\n[2/3] Screening with cheap model (threshold={SCREEN_THRESHOLD}) ...")
    candidates = screen_chunks(chunks, api_key=api_key, verbose=verbose)
    if verbose:
        print(f"      {len(candidates)} hypotheses above threshold")

    if screen_only or not candidates:
        return PipelineReport(
            candidate_id=candidate_id,
            package_name=package_name,
            repo_path=str(repo),
            total_chunks=len(chunks),
            screened_count=len(candidates),
            confirmed_count=0,
        )

    # ── Stage 3: Validate (expensive model) ───────────────────────────────────
    if verbose:
        print(f"\n[3/3] Validating {len(candidates)} candidates with expensive model ...")
    results = validate_hypotheses(candidates, api_key=api_key, verbose=verbose)

    severity_order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    min_rank = severity_order[min_severity]
    filtered = [
        r for r in results
        if r.confirmed and severity_order.get(r.severity, 0) >= min_rank
    ]
    filtered.sort(key=lambda r: severity_order.get(r.severity, 0), reverse=True)

    report = PipelineReport(
        candidate_id=candidate_id,
        package_name=package_name,
        repo_path=str(repo),
        total_chunks=len(chunks),
        screened_count=len(candidates),
        confirmed_count=len(filtered),
        results=filtered,
    )

    if verbose:
        print(f"\n{'='*60}")
        print(report.summary())

    return report
