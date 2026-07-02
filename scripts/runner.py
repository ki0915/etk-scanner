"""
runner.py — 비용 제어형 7단계 취약점 탐지 파이프라인 실행기

Usage:
  python scripts/runner.py ETK-CAND-0001 litellm
  python scripts/runner.py ETK-CAND-0001 litellm --repo candidates/ETK-CAND-0001-litellm/repo
  python scripts/runner.py ETK-CAND-0001 litellm --stage 0  # Stage 0만
  python scripts/runner.py ETK-CAND-0001 litellm --no-batch  # 동기 모드
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Windows 콘솔(cp949)에서 유니코드 출력 깨짐 방지
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def _load_dotenv() -> None:
    """프로젝트 루트의 .env를 읽어 환경변수로 (외부 의존성 없이)."""
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in __import__("os").environ:
            __import__("os").environ[key] = val


_load_dotenv()

from pipeline.provider import Provider, BudgetExceededError
from pipeline.graph_builder import build_graph
from pipeline.static_filter import run_static_filter
from pipeline.haiku_screen import run_haiku_screen
from pipeline.graph_rebut import run_graph_rebut
from pipeline.sonnet_verify import run_sonnet_verify
from pipeline.opus_poc import run_opus_poc


def _auto_repo(candidate_id: str) -> Path:
    base = Path(__file__).parent.parent / "candidates"
    matches = sorted(base.glob(f"{candidate_id}*"))
    if not matches:
        raise FileNotFoundError(f"후보 폴더 없음: {candidate_id}")
    return matches[0] / "repo"


def _print_separator(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def run(args: argparse.Namespace) -> None:
    # ── 경로 설정 ──────────────────────────────────────────────────────────
    repo_path = Path(args.repo) if args.repo else _auto_repo(args.candidate_id)
    data_dir = Path(__file__).parent.parent / "data" / args.candidate_id
    data_dir.mkdir(parents=True, exist_ok=True)

    db_path         = data_dir / "graph.db"
    candidates_path = data_dir / "candidates.jsonl"
    hypotheses_path = data_dir / "hypotheses.jsonl"
    survivors_path  = data_dir / "survivors.jsonl"
    verified_path   = data_dir / "verified.jsonl"
    confirmed_path  = data_dir / "confirmed.jsonl"
    fp_path         = data_dir / "false_positive.jsonl"
    metrics_path    = data_dir / "metrics.json"

    budget_cfg = Path(__file__).parent.parent / "config" / "budget.yaml"
    provider = Provider(metrics_path=metrics_path, stage="init")

    start_time = datetime.now()
    print(f"\n{'='*60}")
    print(f"  AI Pentester Pipeline")
    print(f"  후보: {args.candidate_id} | 패키지: {args.package_name}")
    print(f"  레포: {repo_path}")
    print(f"  시작: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    stop_at = args.stage  # None = 전체 실행

    try:
        # ── Stage 0: 그래프 구축 ─────────────────────────────────────────
        _print_separator("Stage 0: 그래프 구축")
        build_graph(repo_path, db_path)
        if stop_at == 0:
            return

        # ── Stage 1: 정적 필터 ───────────────────────────────────────────
        _print_separator("Stage 1: 정적 필터")
        import yaml
        budget = yaml.safe_load(open(budget_cfg, encoding="utf-8"))
        run_static_filter(db_path, candidates_path,
                          max_candidates=budget.get("stage2_max_chunks", 600))
        if stop_at == 1:
            return

        # ── Stage 2: Haiku 가설 생성 ─────────────────────────────────────
        _print_separator("Stage 2: Haiku 가설 생성 (배치)")
        provider.stage = "stage2_haiku"
        run_haiku_screen(
            candidates_path, provider,
            hypotheses_path=hypotheses_path,
            max_chunks=budget.get("stage2_max_chunks", 600),
            use_batch=not args.no_batch,
        )
        if stop_at == 2:
            return

        # ── Stage 3: 그래프 반증 ─────────────────────────────────────────
        _print_separator("Stage 3: 그래프 반증 (LLM 0)")
        run_graph_rebut(hypotheses_path, db_path, survivors_path)
        if stop_at == 3:
            return

        # Stage 4-1 진입 건수 가드레일
        candidates_count = len(_load_jsonl(candidates_path))
        survivors_count = len(_load_jsonl(survivors_path))
        if candidates_count > 0 and survivors_count / candidates_count > 0.05:
            print(f"\n[!!] 경고: Stage 3 생존율 {survivors_count/candidates_count:.1%} > 5%")
            print("  앞단 필터가 새고 있을 수 있습니다. gates.yaml을 확인하세요.")
            if not args.force:
                print("  --force 옵션으로 강제 진행 가능.")
                return

        # ── Stage 4-1: Sonnet 1차 검증 ───────────────────────────────────
        _print_separator("Stage 4-1: Sonnet 1차 검증")
        provider.stage = "stage4_1_sonnet"
        run_sonnet_verify(
            survivors_path, provider,
            verified_path=verified_path,
            max_candidates=budget.get("stage4_1_max_candidates", 60),
        )
        if stop_at == 4:
            return

        # ── Stage 4-2: Opus PoC ──────────────────────────────────────────
        _print_separator("Stage 4-2: Opus 최종 + PoC 실행")
        provider.stage = "stage4_2_opus"
        run_opus_poc(
            verified_path, provider,
            confirmed_path=confirmed_path,
            fp_path=fp_path,
            max_candidates=budget.get("stage4_2_max_candidates", 25),
            package=args.package_name,
            repo_path=str(repo_path),
        )

    except BudgetExceededError as e:
        print(f"\n🚫 예산 초과 — 중단: {e}")
        print(f"   현재까지 저장된 결과: {data_dir}")

    finally:
        # ── 최종 리포트 ──────────────────────────────────────────────────
        elapsed = (datetime.now() - start_time).total_seconds()
        _print_separator("최종 리포트")

        limit = budget.get("total_budget_krw", 5000)
        spent = provider._metrics.total_cost_krw
        over = spent > limit

        status = "[!!] 예산 초과!" if over else "[OK] 예산 내"
        print(f"{status} {spent:.0f}원 / {limit:.0f}원 (${provider._metrics.total_cost_usd:.4f})")
        print(f"소요 시간: {elapsed:.0f}초")
        print()

        stages = [
            ("Stage 1 후보",   candidates_path),
            ("Stage 2 가설",   hypotheses_path),
            ("Stage 3 생존",   survivors_path),
            ("Stage 4-1 검증", verified_path),
            ("확정 취약점",    confirmed_path),
            ("거짓 양성",      fp_path),
        ]
        for label, path in stages:
            count = len(_load_jsonl(path)) if path.exists() else 0
            print(f"  {label:<15}: {count}개")

        print()
        confirmed = _load_jsonl(confirmed_path)
        if confirmed:
            print("## 확정된 취약점")
            for c in confirmed:
                print(f"  [{c.get('vuln_class','?')}] {c.get('sink_name','?')}")
                print(f"    entry: {c.get('entry_name','?')}")
                print(f"    {c.get('min_repro','')}")
                print()

        fp = _load_jsonl(fp_path)
        if fp:
            print("## 거짓 양성 사유")
            for f in fp:
                print(f"  {f.get('fp_reason','?')} — {f.get('vuln_class','?')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Pentester Pipeline")
    parser.add_argument("candidate_id", help="ETK-CAND-XXXX")
    parser.add_argument("package_name", help="패키지 이름")
    parser.add_argument("--repo", default=None)
    parser.add_argument("--stage", type=int, default=None,
                        help="이 단계까지만 실행 (0~4)")
    parser.add_argument("--no-batch", action="store_true",
                        help="배치 API 미사용 (동기 모드)")
    parser.add_argument("--force", action="store_true",
                        help="Stage 3 생존율 경고 무시")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
