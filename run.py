"""
CVE 취약점 발굴 파이프라인.

사용법:
  python run.py --local candidates/ETK-CAND-0005/repo --etk ETK-CAND-0005
  python run.py --url https://github.com/org/repo      --etk ETK-CAND-0012

파이프라인 단계:
  1. 정적 분석   — AST/Regex로 의심 경로 추출 (LLM 0회)
  2. Haiku 트리아지  — 실제 취약점 여부 1차 판단 (fast/cheap)
  3. Sonnet 심층 분석 — 공격 경로 추적 + PoC 생성 (slow/accurate)
  4. PoC 실행 검증 — subprocess로 실제 실행
  5. DA 리뷰       — PoC 실행 불가 케이스만 LLM 재검토
"""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path

# Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

from pipeline import context, poc
from pipeline import chunker, taint
from pipeline.llm import LLMClient
from pipeline.models import DeepAnalysis


# ─────────────────────────────────────────────────────────────────────────────

def run(repo_dir: Path, work_dir: Path) -> list[DeepAnalysis]:
    llm = LLMClient()
    work_dir.mkdir(parents=True, exist_ok=True)

    # ── Stage 1: 청크 분할 + 소스→싱크 테인트 경로 구성 ─────────────────────
    print("\n[1] 청크 분할 + 테인트 경로 분석 중...")
    all_chunks   = chunker.build_chunks(repo_dir)
    hot_chunks   = chunker.interesting_chunks(all_chunks)
    taint_paths  = taint.find_taint_paths(
        taint.build_call_graph(all_chunks), all_chunks
    )
    print(f"    함수 {len(all_chunks)}개 → 관심 청크 {len(hot_chunks)}개 "
          f"/ 소스→싱크 경로 {len(taint_paths)}개")

    readme_summary = _readme_summary(repo_dir, llm)

    # ── Stage 2: Haiku 가설 생성 ─────────────────────────────────────────────
    print("\n[2] Haiku 가설 생성 중...")
    if taint_paths:
        # 우선순위: HTTP 소스 → RCE/SQLi 싱크 경로만 선별
        high_priority = _prioritize_paths(taint_paths)
        target_paths  = high_priority[:12] if high_priority else taint_paths[:12]
        print(f"    우선순위 경로: {len(high_priority)}개 → 상위 {len(target_paths)}개 분석")
        findings = llm.hypothesize_paths(target_paths, readme_summary)
        if not findings and hot_chunks:
            # 경로 분석 결과 없으면 청크 기반 폴백
            print("    경로 분석 결과 없음 → 청크 기반 폴백...")
            findings = llm.generate_hypotheses(hot_chunks, readme_summary)
    elif hot_chunks:
        findings = llm.generate_hypotheses(hot_chunks, readme_summary)
    else:
        print("    관심 청크 없음 → 라이브러리 직접 분석 모드")
        findings = _library_mode(repo_dir, llm, readme_summary)

    if not findings:
        print("    유효 후보 없음. 종료.")
        return []

    print(f"    {len(findings)}개 후보 발견:")
    for f in findings:
        print(f"      [{f.vuln_type}] conf={f.confidence:.2f}  {f.affected_file}:{f.affected_line}")

    # confidence 0.5 미만 제거, 상위 5개만 Sonnet으로 (Rate limit 방지)
    go_list = sorted(
        [f for f in findings if f.confidence >= 0.5],
        key=lambda f: f.confidence, reverse=True
    )[:5]
    if not go_list:
        print("    전체 confidence 낮음. 종료.")
        return []

    # ── Stage 3: Sonnet 심층 분석 + PoC 생성 ─────────────────────────────────
    print(f"\n[3] Sonnet 심층 분석 (상위 {len(go_list)}개)...")
    analyses: list[tuple[DeepAnalysis, str]] = []  # (analysis, ctx)
    for finding in go_list:
        ctx = context.collect_context(repo_dir, finding.affected_file, finding.affected_line)
        if not ctx:
            print(f"    [{finding.vuln_type}] 파일 읽기 실패, 스킵")
            continue
        result = llm.analyze(finding, ctx, package_name=repo_dir.name)
        if result:
            print(f"    [{result.vuln_type}] conf={result.confidence:.2f}  PoC 생성됨")
            analyses.append((result, ctx))
        else:
            print(f"    [{finding.vuln_type}] confidence 낮음, 스킵")

    if not analyses:
        print("    PoC 생성 실패. 종료.")
        return []

    # ── Stage 4: PoC 실행 검증 ────────────────────────────────────────────────
    print(f"\n[4] PoC 실행 검증 ({len(analyses)}개)...")
    confirmed: list[DeepAnalysis] = []
    unverified: list[tuple[DeepAnalysis, str]] = []

    for analysis, ctx in analyses:
        result = poc.run(analysis.poc_code, package_name=repo_dir.name)
        if result.vulnerable:
            print(f"    ✓ VULNERABLE: {result.evidence}")
            confirmed.append(analysis)
        elif result.executed:
            print(f"    ✗ 실행됨, 미확인 (exit={result.exit_code})")
            unverified.append((analysis, ctx))
        else:
            print(f"    ✗ 실행 실패: {result.error_msg}")
            unverified.append((analysis, ctx))

    # ── Stage 5: DA 리뷰 (PoC 미확인 케이스만) ───────────────────────────────
    if unverified:
        print(f"\n[5] DA 리뷰 ({len(unverified)}개)...")
        for analysis, ctx in unverified:
            da = llm.da_review(analysis, ctx, package_name=repo_dir.name)
            status = "survived" if da.da_survived else "rejected"
            print(f"    [{analysis.vuln_type}] {status}  conf={da.final_confidence:.2f}")
            print(f"      {da.rebuttal[:120]}")
            if da.da_survived:
                confirmed.append(analysis)

    # ── 결과 저장 ─────────────────────────────────────────────────────────────
    if confirmed:
        out = work_dir / "vulns.json"
        out.write_text(
            json.dumps([c.model_dump() for c in confirmed], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n✓ {len(confirmed)}개 취약점 → {out}")
        for c in confirmed:
            print(f"  [{c.vuln_type}] CVSS {c.cvss_score}  {c.description[:80]}")
    else:
        print("\n확인된 취약점 없음.")

    return confirmed


# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

def _prioritize_paths(paths: list) -> list:
    """HTTP 소스 + RCE/SQLi 싱크 경로 우선 선별."""
    HTTP  = {"request.", "args", "body", "cookies", "query", "params"}
    CRIT  = {"exec(", "compile(", "eval(", "execute(", "subprocess", "os.system", "pickle"}
    high  = [p for p in paths
             if any(h in s for s in p.source_chunk.sources for h in HTTP)
             and any(c in d for d in p.sink_chunk.dangers for c in CRIT)]
    # 경로 길이가 짧을수록 더 직접적
    return sorted(high, key=lambda p: len(p.path_names))


def _readme_summary(repo_dir: Path, llm: LLMClient) -> str:
    for name in ["README.md", "README.rst", "README.txt"]:
        p = repo_dir / name
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="ignore")[:4000]
            return llm.summarize_readme(text)
    return ""


def _format_static_results(results) -> str:
    parts = []
    for r in results:
        for p in r.suspicious_paths:
            parts.append(
                f"[{p.vuln_type}] {p.file}:{p.sink_line} "
                f"sink={p.sink_name} source={p.source_hint}\n{p.code_snippet}"
            )
    return "\n---\n".join(parts[:20])


def _library_mode(repo_dir: Path, llm: LLMClient, readme_summary: str):
    """정적 분석이 빈 경우: 큰 소스 파일 직접 분석."""
    skip = {".git", "__pycache__", "node_modules", "dist", "build", "tests", "test", "spec"}
    candidates = []
    for ext in ["*.py", "*.ts", "*.js"]:
        for f in repo_dir.rglob(ext):
            if any(p in skip for p in f.parts):
                continue
            try:
                candidates.append((f.stat().st_size, f))
            except Exception:
                pass
    candidates.sort(reverse=True)

    for _, f in candidates[:5]:
        content = f.read_text(encoding="utf-8", errors="ignore")
        rel = str(f.relative_to(repo_dir))
        print(f"    라이브러리 모드: {rel}")
        found = llm.triage_library(content, rel, repo_dir.name, readme_summary)
        if found:
            return found
    return []


# ── CLI ───────────────────────────────────────────────────────────────────────

def _clone(url: str, dest: Path):
    if not (dest / ".git").exists():
        print(f"git clone {url}")
        subprocess.run(["git", "clone", "--depth=1", url, str(dest)], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE 취약점 발굴 파이프라인")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url",   help="GitHub URL")
    group.add_argument("--local", help="이미 clone된 로컬 경로")
    parser.add_argument("--etk",  default="ETK-CAND-TEST", help="ETK-CAND-XXXX ID")
    args = parser.parse_args()

    work_dir = Path("candidates") / args.etk
    repo_dir = work_dir / "repo"

    if args.url:
        _clone(args.url, repo_dir)
    else:
        repo_dir = Path(args.local)

    run(repo_dir, work_dir)
