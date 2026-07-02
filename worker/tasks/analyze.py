"""
메인 분석 파이프라인 태스크.

vulnhuntr 대비 토큰 절약 포인트:
  - Stage 1: LLM 0회 (AST 정적 분석으로 의심 경로만 추출)
  - Stage 2: Haiku 1회 (전체 7개 vuln type 동시 판단)
  - Stage 3: Sonnet 1회 per vuln (PoC + DA 리뷰 단일 호출 + 프롬프트 캐싱)
  vs vulnhuntr: Sonnet 최대 49회 (7 type × 7 iteration)
"""

import subprocess
from pathlib import Path

from worker.celery_app import celery_app
from worker.static_analyzer import analyze_repo, StaticAnalysisResult
from worker.claude_client import ClaudeClient, VulnFinding, DeepAnalysis


CANDIDATES_DIR = Path(__file__).parent.parent.parent / "candidates"
REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def analyze_candidate(self, etk_id: str, github_url: str):
    """
    ETK-CAND 하나를 완전 분석하는 메인 태스크.
    Phase 1 → 2 → 3 순서로 진행, 각 단계에서 조기 종료 가능.
    """
    work_dir = CANDIDATES_DIR / f"{etk_id}"
    repo_dir = work_dir / "repo"
    work_dir.mkdir(parents=True, exist_ok=True)

    claude = ClaudeClient()
    results: list[DeepAnalysis] = []

    try:
        # ── Phase 1: git clone ──────────────────────────────────────────────
        _update_status(etk_id, "cloning")
        if not (repo_dir / ".git").exists():
            subprocess.run(
                ["git", "clone", "--depth=1", github_url, str(repo_dir)],
                check=True, capture_output=True, timeout=120,
            )

        # ── Phase 1: README 요약 (Haiku, 1회) ──────────────────────────────
        readme = _read_readme(repo_dir)
        readme_summary = claude.summarize_readme(readme) if readme else "README 없음"

        # ── Stage 1: 정적 분석 (LLM 0회) ──────────────────────────────────
        _update_status(etk_id, "static_analysis")
        static_results = analyze_repo(str(repo_dir))

        if not static_results:
            _update_status(etk_id, "stop", "정적 분석: 의심 경로 없음 (LLM 미호출)")
            return {"etk_id": etk_id, "status": "stop", "vulns": []}

        # 의심 경로를 텍스트로 직렬화 (Haiku에 전달할 최소 컨텍스트)
        suspicious_text = _format_suspicious_paths(static_results)

        # ── Stage 2: Haiku Triage (1회 호출) ───────────────────────────────
        _update_status(etk_id, "triage")
        findings: list[VulnFinding] = claude.triage(suspicious_text, readme_summary)

        if not findings:
            _update_status(etk_id, "stop", "Haiku 트리아지: 유효 취약점 없음")
            return {"etk_id": etk_id, "status": "stop", "vulns": []}

        # ── Stage 3: Sonnet 심층 분석 (finding당 1회) ──────────────────────
        _update_status(etk_id, "deep_analysis")
        for finding in findings:
            file_content = _read_file(repo_dir, finding.affected_file)
            if not file_content:
                continue

            # 파일 크기가 너무 크면 의심 함수 주변만 잘라서 전송
            if len(file_content) > 40_000:
                file_content = _extract_relevant_section(file_content, finding.affected_line)

            deep = claude.deep_analyze(
                finding=finding,
                file_content=file_content,
                package_name=etk_id.split("-")[-1],   # 실제론 DB에서 조회
                package_version="latest",
            )
            if deep:
                results.append(deep)
                _save_vuln(work_dir, deep)

        if results:
            _update_status(etk_id, "go", f"{len(results)}개 취약점 확인됨")
            _trigger_report(etk_id, results)
        else:
            _update_status(etk_id, "stop", "DA 리뷰 탈락")

        return {
            "etk_id": etk_id,
            "status": "go" if results else "stop",
            "vulns": [r.model_dump() for r in results],
        }

    except subprocess.CalledProcessError as e:
        raise self.retry(exc=RuntimeError(f"git clone 실패: {e.stderr}"))
    except Exception as e:
        _update_status(etk_id, "error", str(e))
        raise


# ── 리포트 생성 태스크 ──────────────────────────────────────────────────────

@celery_app.task
def generate_report(etk_id: str, package_name: str, weekly_downloads: int):
    """
    GO 판정된 취약점에 대해 최종 CVE 리포트 생성.
    이미 Sonnet 분석 결과가 DB에 있으므로 추가 LLM 호출 최소화.
    """
    from datetime import datetime, timezone
    import json

    vuln_file = CANDIDATES_DIR / etk_id / "vulns.json"
    if not vuln_file.exists():
        return

    vulns = json.loads(vuln_file.read_text())
    report_dir = REPORTS_DIR / etk_id
    report_dir.mkdir(parents=True, exist_ok=True)

    for vuln in vulns:
        report_path = report_dir / f"{package_name}-{vuln['vuln_type'].lower()}-report.md"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        content = f"""# {package_name} — {vuln['vuln_type']} 취약점 리포트

| 항목 | 내용 |
|------|------|
| 작성 시간 | {now} |
| CVSS 4.0 Score | {vuln.get('cvss_score', 'N/A')} |
| 주간 다운로드 수 | {weekly_downloads:,} |
| 취약점 타입 | {vuln['vuln_type']} |

## 요약
{vuln['description']}

## 근본 원인
{vuln['root_cause']}

## PoC
```python
{vuln['poc_code']}
```

## DA 검토 결과
{vuln['da_rebuttal']}

**DA 통과**: {'Yes' if vuln['da_survived'] else 'No'}

## CVSS Vector
`{vuln.get('cvss_vector', '')}`
"""
        report_path.write_text(content, encoding="utf-8")

    return {"etk_id": etk_id, "reports": len(vulns)}


# ── 헬퍼 함수 ──────────────────────────────────────────────────────────────

def _read_readme(repo_dir: Path) -> str:
    for name in ["README.md", "README.rst", "README.txt", "README"]:
        p = repo_dir / name
        if p.exists():
            return p.read_text(encoding="utf-8", errors="ignore")[:4000]
    return ""


def _read_file(repo_dir: Path, file_path: str) -> str:
    target = repo_dir / file_path.lstrip("/")
    if not target.exists():
        # 경로가 정확하지 않을 때 파일명으로 검색
        matches = list(repo_dir.rglob(Path(file_path).name))
        if not matches:
            return ""
        target = matches[0]
    return target.read_text(encoding="utf-8", errors="ignore")


def _extract_relevant_section(content: str, center_line: int | None, window: int = 150) -> str:
    """대용량 파일에서 취약 라인 주변 N줄만 추출."""
    if not center_line:
        return content[:10_000]
    lines = content.splitlines()
    start = max(0, center_line - window)
    end = min(len(lines), center_line + window)
    return "\n".join(lines[start:end])


def _format_suspicious_paths(results: list[StaticAnalysisResult]) -> str:
    parts = []
    for r in results:
        for path in r.suspicious_paths:
            parts.append(
                f"[{path.vuln_type}] {path.file}:{path.sink_line} "
                f"sink={path.sink_name} source_hint={path.source_hint}\n"
                f"{path.code_snippet}\n"
            )
    return "\n---\n".join(parts[:20])  # 최대 20개로 제한 (토큰 절약)


def _save_vuln(work_dir: Path, deep: DeepAnalysis):
    import json
    vuln_file = work_dir / "vulns.json"
    existing = json.loads(vuln_file.read_text()) if vuln_file.exists() else []
    existing.append(deep.model_dump())
    vuln_file.write_text(json.dumps(existing, ensure_ascii=False, indent=2))


def _update_status(etk_id: str, status: str, note: str = ""):
    # 실제 구현에서는 PostgreSQL 업데이트
    print(f"[{etk_id}] status={status} {note}")


def _trigger_report(etk_id: str, results: list[DeepAnalysis]):
    # 리포트 생성 태스크를 별도 큐로 위임
    pass
