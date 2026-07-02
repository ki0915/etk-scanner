"""
security_filter.py — 보안영향 필터 (단일턴, 싸게)

검증 에이전트가 confirmed한 "진짜 버그"를 받아,
"보안 취약점인가 vs 단순 기능 버그인가"를 단일 API 호출로 판정.

비싼 멀티턴 게이트 대신 단일턴 분류 (후보당 ~30원).

교훈 (validators 검증):
  - _isin_checksum: 체크섬 미검증 → 진짜 버그지만 기능 버그 (공격자 이득 없음)
  - cron: step 범위 미검증 → 진짜 버그지만 기능 버그
  - _check_private_ip: IPv6 미분류 → 진짜 + 보안 취약점 (SSRF)
이 셋을 구분하는 게 이 필터의 역할.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.provider import Provider

FILTER_MODEL = "claude-sonnet-4-6"   # 보안 판단은 신중히, 단일턴이라 저렴


_SYSTEM = """\
You are a security triage lead. You receive a CONFIRMED real bug (the behavior is
verified to exist). Decide in a SINGLE response whether it is a REPORTABLE SECURITY
VULNERABILITY or merely a FUNCTIONAL/CORRECTNESS bug.

A bug is a SECURITY VULNERABILITY only if an attacker gains something by exploiting it:
- crosses a security boundary (authz/authn bypass, SSRF, injection, RCE, info leak)
- defeats a control that software relies on for security
- causes DoS

It is a FUNCTIONAL BUG (NOT reportable as a vuln) if it is just incorrect behavior with
no attacker advantage:
- a checksum/format validator that accepts invalid-but-harmless input (e.g. ISIN/CUSIP
  checksum not verified, cron step out of range) — the caller gets a wrong bool but no
  attacker gains access/data/control
- overly lenient or overly strict validation with no security consequence

Key test: "What does an ATTACKER concretely GAIN?" If you cannot name a concrete gain
(access, data, code exec, bypass of a relied-upon control, DoS), it is NOT a vulnerability.

Be strict. Maintainers reject "this validator is too lenient" reports that lack a
security consequence. Most validation-laxity bugs are NOT CVEs.

Output ONLY this JSON:
{
  "is_security_vuln": true | false,
  "attacker_gain": "concrete thing attacker gains (or 'none — functional bug only')",
  "security_boundary": "boundary crossed, or 'none'",
  "severity": "critical|high|medium|low|none",
  "reason": "one sentence why it is / isn't a security vuln",
  "confidence": 0.0
}"""


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


def filter_security(
    confirmed: list[dict],
    provider: Provider,
    verbose: bool = True,
) -> list[dict]:
    """confirmed 버그 중 보안 취약점만 반환. 각 후보당 단일 호출."""
    reportable = []
    print(f"\n  [보안영향 필터 - {FILTER_MODEL}] {len(confirmed)}개 버그 심사 (단일턴)")
    for i, c in enumerate(confirmed, 1):
        seed = c.get("_seed", {})
        user = (
            f"Confirmed bug in function: {seed.get('entry_name','?')}\n"
            f"Vuln class (proposed): {c.get('vuln_class','?')}\n"
            f"Security intent: {c.get('security_intent','?')}\n"
            f"What the bug is: {c.get('reasoning','?')}\n"
            f"Attack vector claimed: {c.get('attack_vector','?')}\n"
            f"PoC result: {c.get('poc_result','?')}\n\n"
            f"Is this a reportable SECURITY VULNERABILITY or just a functional bug?"
        )
        resp = provider.chat(
            model=FILTER_MODEL,
            messages=[{"role": "user", "content": user}],
            system=_SYSTEM,
            max_tokens=600,
            cache_system=True,
        )
        v = _parse(resp["content"])
        name = seed.get("entry_name", "?")
        if v and v.get("is_security_vuln"):
            c["security_filter"] = v
            reportable.append(c)
            if verbose:
                print(f"    [{i}/{len(confirmed)}] {name}: SECURITY "
                      f"[{v.get('severity','?')}] — {v.get('attacker_gain','')[:50]}")
        else:
            gain = (v or {}).get("attacker_gain", "?")
            if verbose:
                print(f"    [{i}/{len(confirmed)}] {name}: 기능버그 (탈락) — {gain[:50]}")

    print(f"  보안 취약점: {len(reportable)}/{len(confirmed)}")
    print(f"  {provider.summary()}")
    return reportable
