"""
bench.py — 비용 벤치마크: 우리 파이프라인 vs 동목적 LLM 스캐너

증명 원칙: 추정 금지. 같은 입력 → 각 도구의 '자기 로그'에서 실측.
  - 우리:      metrics.json (provider.py가 호출마다 기록)
  - Vulnhuntr: 자체 출력 로그 (오픈소스 LLM 취약점 스캐너, 동목적 대조군)

산출: 표 (도구 / 토큰 / 비용 / 발견 / 시간) + bench_result.json

Usage:
  # 우리만 (Vulnhuntr 미설치 시)
  python scripts/bench.py <repo> --package <name>

  # 대조군 포함 (vulnhuntr 설치 후)
  python scripts/bench.py <repo> --package <name> --with-vulnhuntr

NOTE: LLM 실행은 ANTHROPIC_API_KEY + 크레딧 필요. 크레딧 0이면 --dry로 골격만 확인.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

KRW_PER_USD = 1400


# ── 우리 파이프라인 실측 ──────────────────────────────────────────────────────

def run_ours(repo: Path, package: str, budget: int, dry: bool) -> dict:
    """scan.py --mode llm 실행 → metrics.json 파싱."""
    metrics_path = Path("bench_ours_metrics.json")
    if dry:
        return {"tool": "ETK-Scanner", "tokens": None, "cost_krw": None,
                "findings": None, "sec": None, "note": "dry — API 미실행"}

    t0 = time.time()
    from pipeline.provider import Provider
    from pipeline.screen_single import screen_candidates
    from pipeline.intent_finder import build_intent_seeds

    prov = Provider(metrics_path=metrics_path, stage="bench")
    prov._budget["total_budget_krw"] = budget
    seeds = build_intent_seeds(repo, max_seeds=40)
    survivors = screen_candidates(seeds, prov, verbose=False)

    m = prov._metrics
    in_tok = sum(r.input_tokens + r.cache_read_tokens + r.cache_write_tokens
                 for r in m.records)
    out_tok = sum(r.output_tokens for r in m.records)
    return {
        "tool": "ETK-Scanner (ours)",
        "tokens": in_tok + out_tok,
        "in_tokens": in_tok,
        "out_tokens": out_tok,
        "cost_krw": round(m.total_cost_krw, 1),
        "findings": len(survivors),
        "sec": round(time.time() - t0, 1),
        "source": str(metrics_path),
    }


# ── Vulnhuntr 대조군 실측 ─────────────────────────────────────────────────────

def run_vulnhuntr(repo: Path, dry: bool) -> dict:
    """
    Vulnhuntr 실행 → 자체 로그에서 토큰 파싱.
    Vulnhuntr는 각 분석에 사용한 usage를 출력함(claude/gpt usage).
    설치: pipx install vulnhuntr  (또는 pip)
    """
    if dry:
        return {"tool": "Vulnhuntr", "tokens": None, "cost_krw": None,
                "findings": None, "sec": None, "note": "dry — 미실행"}

    t0 = time.time()
    try:
        # vulnhuntr는 -r <repo> 로 실행, stdout/로그에 usage 출력
        proc = subprocess.run(
            ["vulnhuntr", "-r", str(repo)],
            capture_output=True, text=True, timeout=1800,
            encoding="utf-8", errors="replace",
        )
        out = proc.stdout + proc.stderr
    except FileNotFoundError:
        return {"tool": "Vulnhuntr", "note": "미설치 (pipx install vulnhuntr)"}
    except subprocess.TimeoutExpired:
        return {"tool": "Vulnhuntr", "note": "timeout 30min"}

    # Vulnhuntr 출력에서 토큰/발견 파싱 (버전마다 포맷 다름 — 로그 저장 후 수동 확인)
    Path("bench_vulnhuntr.log").write_text(out, encoding="utf-8")
    tokens = _grep_tokens(out)
    return {
        "tool": "Vulnhuntr",
        "tokens": tokens,
        "cost_krw": None,   # 모델·가격 확인 후 계산
        "findings": out.lower().count("confidence"),  # 근사 — 로그 확인 필요
        "sec": round(time.time() - t0, 1),
        "source": "bench_vulnhuntr.log",
        "note": "토큰/발견은 bench_vulnhuntr.log 수동 확인 권장",
    }


def _grep_tokens(text: str) -> int | None:
    """로그에서 토큰 수 추정 파싱 (input_tokens/output_tokens 등)."""
    import re
    total = 0
    found = False
    for m in re.finditer(r"(?:input|output|total)_tokens[\"']?\s*[:=]\s*(\d+)", text):
        total += int(m.group(1))
        found = True
    return total if found else None


# ── 표 출력 ───────────────────────────────────────────────────────────────────

def print_table(rows: list[dict]) -> None:
    print(f"\n{'도구':<22} {'토큰':>10} {'비용(원)':>10} {'발견':>6} {'시간(s)':>8}")
    print("-" * 60)
    for r in rows:
        tok = r.get("tokens")
        cost = r.get("cost_krw")
        find = r.get("findings")
        sec = r.get("sec")
        print(f"{r['tool']:<22} "
              f"{(str(tok) if tok is not None else '-'):>10} "
              f"{(str(cost) if cost is not None else '-'):>10} "
              f"{(str(find) if find is not None else '-'):>6} "
              f"{(str(sec) if sec is not None else '-'):>8}")
        if r.get("note"):
            print(f"  └ {r['note']}")

    # 배수 계산 (둘 다 토큰 있으면)
    ours = next((r for r in rows if "ETK" in r["tool"]), None)
    comp = next((r for r in rows if "Vulnhuntr" in r["tool"]), None)
    if ours and comp and ours.get("tokens") and comp.get("tokens"):
        ratio = comp["tokens"] / ours["tokens"]
        print(f"\n>> 우리가 Vulnhuntr 대비 토큰 {ratio:.1f}배 적음")


def _load_dotenv() -> None:
    import os
    env = Path(__file__).parent.parent / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main() -> None:
    ap = argparse.ArgumentParser(description="비용 벤치마크")
    ap.add_argument("repo")
    ap.add_argument("--package", default="")
    ap.add_argument("--budget", type=int, default=2000)
    ap.add_argument("--with-vulnhuntr", action="store_true")
    ap.add_argument("--dry", action="store_true", help="API 미실행, 골격만")
    args = ap.parse_args()

    _load_dotenv()
    repo = Path(args.repo)
    print(f"[bench] target={repo} package={args.package} dry={args.dry}")

    rows = [run_ours(repo, args.package, args.budget, args.dry)]
    if args.with_vulnhuntr:
        rows.append(run_vulnhuntr(repo, args.dry))

    print_table(rows)

    result = {
        "target": str(repo),
        "package": args.package,
        "rows": rows,
        "timestamp": time.strftime("%Y-%m-%d %H:%M"),
    }
    Path("bench_result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n[출력] bench_result.json")


if __name__ == "__main__":
    main()
