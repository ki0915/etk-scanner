"""
dup_check.py — 중복/기지(旣知) 체크 게이트

신고 전 발견이 이미 알려졌는지 자동 조회한다.
validators 교훈: open-webui advisory에 이미 있던 걸 수동으로야 발견 →
이 단계를 자동화해 "기지 사실"을 신고 전에 거른다. (SkillSpector의 OSV 통합 모방)

2단계:
  1. OSV.dev API로 해당 패키지의 기존 CVE/GHSA 조회 (무료, 키 불필요)
  2. LLM이 발견 내용 vs 기존 CVE 목록을 대조 → 중복 가능성 판정
     + 웹 검색이 필요한 키워드 제안 (사람이 최종 확인)
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from pipeline.provider import Provider

DUP_MODEL = "claude-sonnet-4-6"

_ECOSYSTEMS = ["PyPI", "npm"]


def query_osv(package: str, ecosystem: str = "PyPI") -> list[dict]:
    """OSV.dev에서 패키지의 알려진 취약점 조회."""
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
        out = []
        for v in resp.get("vulns", []):
            out.append({
                "id": v.get("id", ""),
                "summary": v.get("summary", ""),
                "details": (v.get("details", "") or "")[:500],
                "aliases": v.get("aliases", []),
            })
        return out
    except Exception as e:
        return [{"id": "OSV_QUERY_FAILED", "summary": str(e)}]


_SYSTEM = """\
You compare a newly found vulnerability against the list of ALREADY-KNOWN
vulnerabilities for the same package (from OSV.dev). Decide if the new finding is
a duplicate of a known issue, or genuinely novel.

Be careful: a package may have known CVEs that are UNRELATED to this finding
(e.g. a ReDoS CVE is unrelated to an SSRF finding). Only call it a duplicate if a
known entry covers the SAME root cause / same vulnerability.

Also assess: even if not in OSV, does this finding look like it might be publicly
known through other channels (third-party advisories, the library's own docs saying
"not supported", well-known behavior)? Suggest specific web-search queries a human
should run before reporting.

Output ONLY this JSON:
{
  "is_duplicate": true | false,
  "matching_known_id": "GHSA/CVE id if duplicate, else empty",
  "novelty_confidence": 0.0,
  "likely_known_elsewhere": true | false,
  "reasoning": "one sentence",
  "search_queries": ["query a human should run", "..."]
}"""


def check_duplicate(
    finding: dict,
    package: str,
    provider: Provider,
    verbose: bool = True,
) -> dict:
    seed = finding.get("_seed", {})
    # 여러 생태계 조회
    known = []
    for eco in _ECOSYSTEMS:
        known.extend(query_osv(package, eco))

    known_str = "\n".join(
        f"- {k['id']} ({', '.join(k.get('aliases', []))}): {k['summary']}"
        for k in known
    ) or "(OSV에 등록된 취약점 없음)"

    user = (
        f"Package: {package}\n"
        f"New finding — function: {seed.get('entry_name','?')}\n"
        f"vuln_class: {finding.get('vuln_class','?')}\n"
        f"description: {finding.get('reasoning','?')}\n"
        f"attack_vector: {finding.get('attack_vector','?')}\n\n"
        f"Known vulnerabilities for this package (OSV.dev):\n{known_str}\n\n"
        f"Is the new finding a duplicate of a known one, or novel?"
    )
    resp = provider.chat(
        model=DUP_MODEL,
        messages=[{"role": "user", "content": user}],
        system=_SYSTEM,
        max_tokens=600,
        cache_system=True,
    )
    t = resp["content"].strip()
    if "```" in t:
        for p in t.split("```"):
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                t = p
                break
    s, e = t.find("{"), t.rfind("}")
    try:
        verdict = json.loads(t[s:e + 1]) if s != -1 else {}
    except json.JSONDecodeError:
        verdict = {}

    verdict["osv_known"] = known
    if verbose:
        if verdict.get("is_duplicate"):
            print(f"      중복: {verdict.get('matching_known_id','?')}")
        else:
            print(f"      신규 가능성 {verdict.get('novelty_confidence','?')} "
                  f"| 타채널 기지 의심: {verdict.get('likely_known_elsewhere','?')}")
    return verdict


def run_dup_check(
    reportable: list[dict],
    package: str,
    provider: Provider,
    verbose: bool = True,
) -> list[dict]:
    """
    신고 후보를 중복 체크. 명백한 중복은 제외, 나머지는 verdict 첨부해 반환.
    (완전 자동 제외보다는, 사람이 최종 확인하도록 search_queries 제공)
    """
    novel = []
    print(f"\n  [중복 체크 - OSV + {DUP_MODEL}] {len(reportable)}개")
    for i, c in enumerate(reportable, 1):
        name = c.get("_seed", {}).get("entry_name", "?")
        print(f"    [{i}/{len(reportable)}] {name}")
        verdict = check_duplicate(c, package, provider, verbose)
        c["dup_check"] = verdict
        if not verdict.get("is_duplicate"):
            novel.append(c)
    print(f"  신규 후보: {len(novel)}/{len(reportable)} (나머지는 OSV 중복)")
    print(f"  {provider.summary()}")
    return novel
