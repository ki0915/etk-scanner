"""
bench_eval.py — 레이블 데이터셋으로 재현율/CWE정확도/비용 측정

SecurityEval (121개 알려진 취약 Python 코드, ID에 CWE 레이블)에 우리 LLM 티어를
돌려 측정:
  - 재현율(Recall) = 취약 탐지한 샘플 / 전체
  - CWE 정확도 = 탐지 중 CWE 레이블 일치 / 탐지
  - 비용/샘플, 비용당 재현율

정직한 한계: SecurityEval은 안전 샘플이 없어 정밀도(오탐)는 측정 불가.
정밀도는 별도 안전 코드셋 필요.

Usage:
  python scripts/bench_eval.py --dataset bench_data/SecurityEval/dataset.jsonl
  python scripts/bench_eval.py --limit 20        # 빠른 확인
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def _load_dotenv() -> None:
    import os
    env = Path(__file__).parent.parent / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

from pipeline.provider import Provider

MODEL = "claude-haiku-4-5-20251001"

_SYSTEM = """\
You are a security code reviewer. Given a Python snippet, decide if it contains a
security vulnerability. Be precise. Output ONLY JSON:
{"vulnerable": true|false, "cwe": "CWE-XXX or empty", "reason": "one line"}"""


def _cwe_norm(cwe: str) -> str:
    """CWE-020, CWE-20 → '20' (0패딩/형식 차이 정규화)."""
    m = re.search(r"CWE[-_ ]?(\d+)", cwe or "", re.IGNORECASE)
    return str(int(m.group(1))) if m else ""


def _cwe_from_id(sample_id: str) -> str:
    return _cwe_norm(sample_id)


def _parse(text: str) -> dict | None:
    t = text.strip()
    if "```" in t:
        for p in t.split("```"):
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                t = p
                break
    s, e = t.find("{"), t.rfind("}")
    if s == -1 or e < s:
        return None
    try:
        return json.loads(t[s:e + 1])
    except json.JSONDecodeError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="bench_data/SecurityEval/dataset.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="bench_eval_result.json")
    args = ap.parse_args()

    samples = []
    for line in Path(args.dataset).read_text(encoding="utf-8").splitlines():
        if line.strip():
            samples.append(json.loads(line))
    if args.limit:
        samples = samples[:args.limit]

    prov = Provider(metrics_path="bench_eval_metrics.json", stage="bench_eval")

    detected = 0
    cwe_match = 0
    per_cwe = {}
    total = len(samples)

    print(f"[bench] SecurityEval {total}개 | model={MODEL}")
    for i, s in enumerate(samples, 1):
        code = s.get("Insecure_code", "")
        label_cwe = _cwe_from_id(s["ID"])
        per_cwe.setdefault(label_cwe, {"n": 0, "hit": 0})
        per_cwe[label_cwe]["n"] += 1

        try:
            resp = prov.chat(model=MODEL,
                             messages=[{"role": "user", "content": code[:3000]}],
                             system=_SYSTEM, max_tokens=256, cache_system=True)
        except Exception as e:
            print(f"  [{i}/{total}] {s['ID']} ERROR {e}")
            continue

        v = _parse(resp["content"]) or {}
        is_vuln = bool(v.get("vulnerable"))
        pred_cwe = _cwe_norm(v.get("cwe") or "")

        if is_vuln:
            detected += 1
            per_cwe[label_cwe]["hit"] += 1
            if pred_cwe == label_cwe:
                cwe_match += 1

        if i % 20 == 0:
            print(f"  {i}/{total} | 탐지 {detected} | {prov._metrics.total_cost_krw:.0f}원")

    recall = detected / total if total else 0
    cwe_acc = cwe_match / detected if detected else 0
    cost = prov._metrics.total_cost_krw
    tok = sum(r.input_tokens + r.output_tokens + r.cache_read_tokens + r.cache_write_tokens
              for r in prov._metrics.records)

    print("\n" + "=" * 50)
    print(f"재현율(Recall)     : {recall:.1%}  ({detected}/{total})")
    print(f"CWE 정확도         : {cwe_acc:.1%}  (탐지 중 CWE 일치)")
    print(f"총 비용            : {cost:.0f}원  ({tok:,} 토큰)")
    print(f"비용/샘플          : {cost/total:.2f}원")
    print(f"비용당 재현율      : {recall/(cost/1000):.2f} (recall per 1000원)" if cost else "")
    print("=" * 50)
    print("주의: SecurityEval은 안전 샘플 없음 → 정밀도(오탐) 미측정")

    result = {
        "dataset": "SecurityEval", "samples": total,
        "recall": round(recall, 4), "cwe_accuracy": round(cwe_acc, 4),
        "detected": detected, "cost_krw": round(cost, 1),
        "cost_per_sample_krw": round(cost / total, 2) if total else 0,
        "tokens": tok,
        "note": "no safe samples -> precision not measured",
    }
    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[출력] {args.out}")


if __name__ == "__main__":
    main()
