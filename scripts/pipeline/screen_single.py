"""
screen_single.py — 단일턴 분류 (GPTScan 모델)

기존: 의도 함수마다 멀티턴 에이전트(8턴) → 비용 폭증
신규: 의도 함수마다 단일 API 호출 1회 → 비용 1/8

각 보안 의도 함수의 코드를 그대로 주고, 단일턴으로:
  "이 함수의 보안 의도가 위반될 가능성이 있는가? 가설과 신뢰도를 내라"
도구 사용 없음. 멀티턴 PoC 검증은 고신뢰 후보에만 별도로.

이것이 핵심 비용 레버: 발굴(넓게 스캔)은 단일턴으로 싸게,
검증(깊게 확인)만 멀티턴 에이전트로.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.provider import Provider

SCREEN_MODEL = "claude-haiku-4-5-20251001"
SCREEN_THRESHOLD = 0.5


_SYSTEM = """\
You are a security researcher triaging security-decision functions for likely
vulnerabilities. You are given ONE function that makes a security judgment
(validate/check/sanitize/parse/classify/allow-deny).

In a SINGLE response (no tools, no investigation), assess whether this function's
security intent is likely VIOLABLE. Focus on classic logic-bug patterns:
- hand-rolled parsing (startswith/regex) that diverges from stdlib/spec
- incomplete enumeration (handles IPv4 but not IPv6; ASCII but not unicode; etc.)
- decode/normalize ordering mistakes (check before decode)
- missing cases a vetted library would handle

Be calibrated. Most functions are fine. Only flag when you can name a SPECIFIC
input class that likely defeats the intent AND a reason the stdlib/spec would
disagree.

Output ONLY this JSON (one line per field, no code):
{
  "suspicious": true | false,
  "vuln_class": "CWE-XXX or short name",
  "security_intent": "what the function is meant to guarantee",
  "suspected_bypass": "specific input class that likely defeats it",
  "why_stdlib_disagrees": "how a vetted lib/spec would handle it differently (or empty)",
  "confidence": 0.0
}
confidence>=0.7 means you have a concrete, testable bypass hypothesis.
confidence<0.5 means probably fine — set suspicious=false."""


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


def screen_candidates(
    seeds: list[dict],
    provider: Provider,
    threshold: float = SCREEN_THRESHOLD,
    verbose: bool = True,
) -> list[dict]:
    """
    각 seed(의도 함수)를 단일턴으로 분류.
    threshold 이상 신뢰도의 가설만 반환 (멀티턴 검증 대상).
    """
    survivors = []
    print(f"\n  [단일턴 분류 - {SCREEN_MODEL}] {len(seeds)}개 함수")
    for i, seed in enumerate(seeds, 1):
        code = seed.get("code", "")
        if not code:
            continue
        user = (
            f"Function: {seed.get('entry_name','?')}\n"
            f"File: {seed.get('file','?')}\n"
            f"Static signals: {seed.get('intent_signals', [])}\n\n"
            f"```python\n{code[:2500]}\n```"
        )
        resp = provider.chat(
            model=SCREEN_MODEL,
            messages=[{"role": "user", "content": user}],
            system=_SYSTEM,
            max_tokens=512,
            cache_system=True,
        )
        v = _parse(resp["content"])
        if not v:
            continue
        conf = float(v.get("confidence", 0))
        if v.get("suspicious") and conf >= threshold:
            v["_seed"] = seed
            survivors.append(v)
            if verbose:
                print(f"    [{i}/{len(seeds)}] {seed.get('entry_name','?')}: "
                      f"[{conf:.2f}] {v.get('suspected_bypass','')[:60]}")

    # 신뢰도순 정렬
    survivors.sort(key=lambda x: float(x.get("confidence", 0)), reverse=True)
    print(f"  분류 통과 (>= {threshold}): {len(survivors)}/{len(seeds)}")
    print(f"  {provider.summary()}")
    return survivors
