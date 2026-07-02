"""
sonnet_verify.py — Stage 4-1: Sonnet 1차 검증

survivors.jsonl 의 각 가설을 Sonnet이 깊이 검토한다.
판정: confirmed_likely / needs_poc / rejected

rejected는 여기서 종료. 나머지만 Opus로 넘긴다.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.provider import Provider

_SYSTEM = """\
You are a senior security researcher verifying a vulnerability hypothesis.
You receive: the hypothesis, the entry point code, the sink code, and the call path.

Verdict options:
- "confirmed_likely": You are confident the vulnerability is real and exploitable as described.
- "needs_poc": The hypothesis is plausible but requires runtime verification to confirm.
- "rejected": The hypothesis is incorrect — input is sanitized, gate exists, or path is unreachable.

Output ONLY valid JSON:
{
  "verdict": "confirmed_likely|needs_poc|rejected",
  "reason": "one paragraph explaining the verdict",
  "missing_gate": "which permission/validation check is absent (if confirmed_likely or needs_poc)",
  "attack_vector": "concrete attack description if confirmed_likely",
  "cvss_estimate": "CVSS:3.1/AV:N/... (best estimate, or empty string)"
}"""


def _build_user_msg(survivor: dict) -> str:
    return (
        f"## Hypothesis\n"
        f"vuln_class: {survivor.get('vuln_class','?')}\n"
        f"entrypoint: {survivor.get('entrypoint','?')}\n"
        f"sink: {survivor.get('sink','?')}\n"
        f"required_gate: {survivor.get('required_gate','?')}\n"
        f"falsification_condition: {survivor.get('falsification_condition','?')}\n"
        f"min_repro: {survivor.get('min_repro','?')}\n"
        f"confidence (haiku): {survivor.get('confidence',0)}\n\n"
        f"## Call path\n{' → '.join(survivor.get('path',[]))}\n\n"
        f"## Entry code\n```python\n{survivor.get('entry_code','')[:2000]}\n```\n\n"
        f"## Sink code\n```python\n{survivor.get('code','')[:2000]}\n```"
    )


def run_sonnet_verify(
    survivors_path: str | Path,
    provider: Provider,
    verified_path: str | Path | None = None,
    max_candidates: int = 60,
) -> Path:
    survivors_path = Path(survivors_path)
    if verified_path is None:
        verified_path = survivors_path.parent / "verified.jsonl"
    verified_path = Path(verified_path)

    survivors = []
    with open(survivors_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                survivors.append(json.loads(line))

    if len(survivors) > max_candidates:
        survivors = survivors[:max_candidates]

    model = "claude-sonnet-4-6"
    results = []

    for i, surv in enumerate(survivors, 1):
        print(f"  [{i}/{len(survivors)}] {surv.get('vuln_class','?')} - {surv.get('sink_name','?')}")

        resp = provider.chat(
            model=model,
            messages=[{"role": "user", "content": _build_user_msg(surv)}],
            system=_SYSTEM,
            max_tokens=1024,
            cache_system=True,
        )

        raw = resp["content"].strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.rsplit("```", 1)[0]

        try:
            verdict_data = json.loads(raw)
        except json.JSONDecodeError:
            verdict_data = {"verdict": "rejected", "reason": "parse error"}

        verdict = verdict_data.get("verdict", "rejected")
        print(f"    → {verdict}")

        results.append({**surv, "sonnet_verdict": verdict_data})

    verified_path.parent.mkdir(parents=True, exist_ok=True)
    with open(verified_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    forwarded = [r for r in results
                 if r["sonnet_verdict"].get("verdict") in ("confirmed_likely", "needs_poc")]
    print(f"  검증: {len(results)} | Opus로 전달: {len(forwarded)}")
    print(f"  비용: {provider.summary()}")
    return verified_path
