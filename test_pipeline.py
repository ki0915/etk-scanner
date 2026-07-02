"""
Celery/Redis 없이 파이프라인을 직접 실행하는 테스트 스크립트.
실제 CVE 발굴 가능 여부를 빠르게 판단하기 위함.

사용법:
  pip install anthropic pydantic
  $env:ANTHROPIC_API_KEY = "sk-ant-..."
  python test_pipeline.py --url https://github.com/xxx/yyy --etk ETK-CAND-0001

  # 또는 이미 clone된 로컬 경로로 테스트:
  python test_pipeline.py --local ./path/to/repo --etk ETK-CAND-0001
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Windows 콘솔 UTF-8 처리
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

# 프로젝트 루트를 sys.path에 추가
sys.path.insert(0, str(Path(__file__).parent))

from worker.static_analyzer import analyze_repo
from worker.claude_client import ClaudeClient
from worker.poc_runner import run_poc
from worker.call_chain import collect_context


def run(github_url: str | None, local_path: str | None, etk_id: str):
    work_dir = Path("candidates") / etk_id
    repo_dir = work_dir / "repo"
    work_dir.mkdir(parents=True, exist_ok=True)

    # ── git clone (URL 지정 시) ─────────────────────────────────────────────
    if github_url:
        if not (repo_dir / ".git").exists():
            print(f"\n[1/4] git clone {github_url}")
            subprocess.run(
                ["git", "clone", "--depth=1", github_url, str(repo_dir)],
                check=True,
            )
        else:
            print(f"\n[1/4] 이미 clone됨: {repo_dir}")
    else:
        repo_dir = Path(local_path)
        print(f"\n[1/4] 로컬 경로 사용: {repo_dir}")

    claude = ClaudeClient()

    # ── README 요약 ────────────────────────────────────────────────────────
    print("\n[2/4] README 요약 중...")
    readme = _read_readme(repo_dir)
    if readme:
        readme_summary = claude.summarize_readme(readme)
        print(f"  → {readme_summary[:200]}...")
    else:
        readme_summary = "README 없음"
        print("  → README 없음")

    # ── Stage 1: 정적 분석 (LLM 0회) ──────────────────────────────────────
    print("\n[3/4] 정적 분석 (LLM 미사용)...")
    static_results = analyze_repo(str(repo_dir))

    if not static_results:
        # ── 라이브러리 모드: Stage 1 우회, 핵심 파일 직접 Haiku에 전달 ──
        print("  → 의심 경로 없음 → 라이브러리 모드 전환")
        findings = _library_mode_triage(repo_dir, claude, readme_summary)
    else:
        total_paths = sum(len(r.suspicious_paths) for r in static_results)
        print(f"  → {len(static_results)}개 파일, {total_paths}개 의심 경로 발견")
        for r in static_results[:5]:
            for p in r.suspicious_paths[:2]:
                print(f"     [{p.vuln_type}] {p.file}:{p.sink_line} sink={p.sink_name}")

        # ── Stage 2: Haiku Triage ──────────────────────────────────────────
        print("\n[4/4] Haiku 트리아지...")
        suspicious_text = _format_paths(static_results)
        findings = claude.triage(suspicious_text, readme_summary)

    if not findings:
        print("  → Haiku: 유효 취약점 없음. STOP")
        return

    print(f"  → {len(findings)}개 후보 발견:")
    for f in findings:
        print(f"     [{f.vuln_type}] confidence={f.confidence:.2f} {f.affected_file}:{f.affected_line}")
        print(f"     {f.description}")

    # ── Stage 3a: Sonnet 심층 분석 + PoC ─────────────────────────────────
    go_list = [f for f in findings if f.confidence >= 0.5]
    if not go_list:
        print("\n  → confidence 0.5 미만. STOP")
        return

    print(f"\n[Stage 3a] Sonnet PoC 생성 중 ({len(go_list)}개)...")
    analyzed = []
    for finding in go_list:
        print(f"\n  [{finding.vuln_type}] {finding.affected_file}:{finding.affected_line}")

        # import 그래프 기반 call chain 수집
        file_content = collect_context(
            repo_dir, finding.affected_file, finding.affected_line
        )
        if not file_content:
            print("  → 파일 읽기 실패, 스킵")
            continue

        deep = claude.deep_analyze(
            finding=finding,
            file_content=file_content,
            package_name=repo_dir.name,
            package_version="latest",
        )
        if deep:
            print(f"  → PoC 생성됨. confidence={deep.confidence:.2f}")
            analyzed.append((deep, file_content))
        else:
            print("  → confidence 낮음. 스킵")

    if not analyzed:
        print("\n최종: PoC 생성 실패")
        return

    # ── Stage 3b: PoC 실행 검증 ────────────────────────────────────────────
    print(f"\n[Stage 3b] PoC 실행 검증 중 ({len(analyzed)}개)...")
    poc_verified = []
    for deep, file_content in analyzed:
        print(f"\n  실행: [{deep.vuln_type}]")
        poc_result = run_poc(
            poc_code=deep.poc_code,
            package_name=repo_dir.name,
            package_version="latest",
            timeout_secs=30,
        )
        if poc_result.vulnerable:
            print(f"  → VULNERABLE 확인! 증거: {poc_result.evidence}")
            poc_verified.append((deep, poc_result))
        elif poc_result.executed:
            print(f"  → 실행됨, 취약점 미확인 (exit={poc_result.exit_code})")
            print(f"     stdout: {poc_result.stdout[:200]}".encode('utf-8', errors='replace').decode('utf-8'))
            if poc_result.stderr:
                print(f"     stderr: {poc_result.stderr[:200]}".encode('utf-8', errors='replace').decode('utf-8'))
        else:
            print(f"  → 실행 실패: {poc_result.error_msg}")

    # PoC 실행 실패한 경우 DA 리뷰로 fallback
    da_candidates = [(d, f) for d, f in analyzed
                     if not any(d.vuln_type == p.vuln_type for p, _ in poc_verified)]

    # ── Stage 3c: DA 리뷰 (PoC 실행 불가한 케이스만) ──────────────────────
    da_confirmed = []
    if da_candidates:
        print(f"\n[Stage 3c] DA 리뷰 ({len(da_candidates)}개 — PoC 실행 불가 케이스)...")
        for deep, file_content in da_candidates:
            print(f"\n  DA 검토: [{deep.vuln_type}]")
            da = claude.da_review(deep, file_content, repo_dir.name)
            print(f"  → survived={da.da_survived} confidence={da.final_confidence:.2f}")
            print(f"     {da.rebuttal[:200]}")
            if da.da_survived:
                da_confirmed.append(deep)

    confirmed = [deep for deep, _ in poc_verified] + da_confirmed

    # ── 결과 저장 ──────────────────────────────────────────────────────────
    if confirmed:
        out = work_dir / "vulns.json"
        out.write_text(json.dumps([c.model_dump() for c in confirmed], ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n결과 저장: {out}")
        print(f"\n최종: {len(confirmed)}개 취약점 확인됨")
        for c in confirmed:
            print(f"  [{c.vuln_type}] CVSS {c.cvss_score} — {c.description[:80]}")
    else:
        print("\n최종: 확인된 취약점 없음")


def _read_readme(repo_dir: Path) -> str:
    for name in ["README.md", "README.rst", "README.txt"]:
        p = repo_dir / name
        if p.exists():
            return p.read_text(encoding="utf-8", errors="ignore")[:4000]
    return ""


def _read_file(repo_dir: Path, file_path: str) -> str:
    target = repo_dir / file_path.lstrip("/")
    if not target.exists():
        matches = list(repo_dir.rglob(Path(file_path).name))
        if not matches:
            return ""
        target = matches[0]
    return target.read_text(encoding="utf-8", errors="ignore")


def _collect_call_chain(repo_dir: Path, finding) -> str:
    """
    싱크 파일 + 연관 파일(라우터, 유틸, 모델)을 합쳐서 Sonnet에 전달할 컨텍스트 생성.
    단순 300줄 조각 대신 실제 attack path에 관련된 코드 전체를 제공.
    """
    parts = []

    # 1. 싱크가 있는 파일 (전체 또는 관련 섹션)
    main_content = _read_file(repo_dir, finding.affected_file)
    if not main_content:
        return ""
    if len(main_content) > 15_000:
        lines = main_content.splitlines()
        cl = finding.affected_line or 1
        # 싱크 주변 ±200줄 (기존보다 넓게)
        section = "\n".join(lines[max(0, cl - 200):cl + 200])
        parts.append(f"# FILE: {finding.affected_file} (relevant section)\n{section}")
    else:
        parts.append(f"# FILE: {finding.affected_file}\n{main_content}")

    # 2. 연관 파일 탐색 (라우터, 뷰, 컨트롤러, 앱 진입점)
    skip = {".git", "__pycache__", "node_modules", "dist", "build", "test", "spec"}
    route_keywords = ["route", "view", "controller", "handler", "app", "router", "endpoint"]
    util_keywords  = ["util", "helper", "sanitize", "escape", "validate", "auth", "middleware"]

    def is_related(f: Path) -> bool:
        name = f.stem.lower()
        return any(k in name for k in route_keywords + util_keywords)

    candidates = []
    for ext in ["*.py", "*.ts", "*.js"]:
        for f in repo_dir.rglob(ext):
            if any(p in skip for p in f.parts):
                continue
            if str(f).replace("\\", "/").endswith(finding.affected_file.replace("\\", "/")):
                continue  # 이미 포함
            if is_related(f):
                candidates.append(f)

    # 관련 파일 최대 3개, 각 최대 5000자
    for f in candidates[:3]:
        content = f.read_text(encoding="utf-8", errors="ignore")
        rel = str(f.relative_to(repo_dir))
        if len(content) > 5000:
            content = content[:5000] + "\n... (truncated)"
        parts.append(f"# FILE: {rel}\n{content}")

    result = "\n\n{'='*60}\n\n".join(parts)
    # 전체 40K 제한
    return result[:40_000]


def _library_mode_triage(repo_dir: Path, claude, readme_summary: str):
    """Stage 1에서 아무것도 못 잡은 경우 핵심 소스 파일을 직접 Haiku에 전달."""
    from worker.static_analyzer import JS_SKIP_DIRS
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules",
            "dist", "build", "tests", "test", "spec"}

    # 가장 큰 소스 파일 순으로 최대 5개 분석
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
    findings = []
    for _, f in candidates[:5]:
        content = f.read_text(encoding="utf-8", errors="ignore")
        rel = str(f.relative_to(repo_dir))
        print(f"  → 라이브러리 모드 분석: {rel} ({len(content)} chars)")
        found = claude.analyze_library(content, rel, repo_dir.name, readme_summary)
        findings.extend(found)
        if findings:
            break  # 첫 번째 파일에서 찾으면 충분

    if findings:
        print(f"  → {len(findings)}개 후보 발견 (라이브러리 모드)")
    else:
        print("  → 라이브러리 모드에서도 취약점 없음. STOP")
    return findings


def _format_paths(results) -> str:
    parts = []
    for r in results:
        for p in r.suspicious_paths:
            parts.append(
                f"[{p.vuln_type}] {p.file}:{p.sink_line} "
                f"sink={p.sink_name} source={p.source_hint}\n{p.code_snippet}"
            )
    return "\n---\n".join(parts[:20])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="GitHub URL")
    parser.add_argument("--local", help="로컬 레포 경로")
    parser.add_argument("--etk", default="ETK-CAND-TEST", help="ETK ID")
    args = parser.parse_args()

    if not args.url and not args.local:
        parser.error("--url 또는 --local 중 하나 필요")

    run(args.url, args.local, args.etk)
