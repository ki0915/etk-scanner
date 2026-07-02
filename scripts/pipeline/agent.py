"""
agent.py — 탐색형 취약점 분석 에이전트

정적 그래프가 준 "시작점(seed)"을 받아, 도구로 코드를 능동 탐색하며
실제 취약점인지 판정한다. 미지의 취약점도 발견 가능.

비용 통제:
  - 1차 조사는 저가 모델(Haiku)로, 턴 수 제한
  - "유망(promising)" 판정만 고가 모델(Opus)로 PoC 검증 단계 진입
  - provider가 예산 누적 추적, 초과 시 중단

피드백 메모리:
  - 거짓양성 패턴을 data/<cand>/fp_memory.jsonl에 누적
  - 다음 실행 시 시스템 프롬프트에 주입해 같은 실수 방지
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.provider import Provider, BudgetExceededError
from pipeline.agent_tools import ToolBox, TOOL_SCHEMAS

TRIAGE_MODEL = "claude-haiku-4-5-20251001"
DEEP_MODEL = "claude-opus-4-8"
MAX_TURNS = 14
TRIAGE_MAX_TURNS = 8   # triage는 짧게 (의도 함수는 단일 함수 조사라 깊이 불필요)


_SYSTEM = """\
You are an autonomous security researcher hunting for REAL, novel vulnerabilities
in a Python package. You are given a SECURITY-DECISION FUNCTION — a function whose
job is to make a security judgment (validate, check, sanitize, normalize, parse,
allow/deny, classify public/private, etc.).

Your goal: determine whether this function's SECURITY INTENT can be VIOLATED.
Most real CVEs are logic bugs, not injection sinks: the function is SUPPOSED to
enforce a security property, but an attacker can craft input that defeats it.

How to investigate:
1. Read the function. Ask: "What security property is this function MEANT to guarantee?"
   (e.g. "only public IPs pass", "only safe XML names pass", "rejects malicious URLs",
    "this input is properly escaped/normalized").
2. Look for HOW it decides. Hand-rolled checks are prime suspects:
   - string prefix/suffix matching (startswith/endswith) instead of proper parsing
   - hand-written regex instead of a vetted library
   - incomplete enumerations (a list of "bad" values that misses cases)
   - decoding/normalization order mistakes (decode after check, normalize after validate)
3. Compare against the CORRECT behavior. The strongest signal:
   - Does Python's STDLIB do this correctly while this code reimplements it wrong?
     (e.g. `ipaddress.is_private` vs hand-rolled prefix matching;
      `email.utils` vs hand-rolled regex). grep_repo / read_file to confirm.
   - Are there RFC/spec cases the code misses (reserved ranges, edge encodings)?
4. **DECISIVE STEP — you MUST run_poc to prove the bypass.** Write a PoC that:
   - imports the REAL package and calls the REAL function
   - feeds a crafted input that SHOULD be rejected/classified-dangerous but ISN'T
     (or vice versa), and compares against stdlib/known-correct answer
   - prints VULNERABLE if the security intent is violated, NOT_REPRODUCED otherwise

Mandatory rule:
- Output 'not_vulnerable' ONLY if (a) you confirmed the function is correct (matches
  stdlib/spec for the cases you tried), OR (b) your PoC failed to show a violation.
- If you suspect a bypass but have not yet proven it, output 'likely' to escalate.

Anti-patterns:
- Do not reimplement the function in your PoC. Import and call the real one.
- Do not claim 'confirmed' without a run_poc that demonstrates the intent violation.
- "It uses a dangerous function" is NOT a finding. "Its security decision can be
  defeated by input X, which stdlib/spec says should be Y" IS a finding.

When done, output ONLY this JSON (no other text, no code fences):
{
  "verdict": "confirmed" | "likely" | "not_vulnerable",
  "vuln_class": "CWE-XXX or short name",
  "security_intent": "what property the function was meant to enforce",
  "reasoning": "how the intent is violated (or why it holds)",
  "attack_vector": "concrete input that defeats it",
  "poc_result": "summary of run_poc output if you ran it, else 'not run'",
  "confidence": 0.0
}
Only 'confirmed' if run_poc actually demonstrated the intent violation against the real package."""


def _load_fp_memory(data_dir: Path) -> str:
    """과거 거짓양성 패턴을 시스템 프롬프트에 주입할 문자열로."""
    fp_file = data_dir / "fp_memory.jsonl"
    if not fp_file.exists():
        return ""
    patterns = []
    for line in fp_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rec = json.loads(line)
                patterns.append(f"- {rec.get('pattern','')}: {rec.get('lesson','')}")
            except json.JSONDecodeError:
                continue
    if not patterns:
        return ""
    return ("\n\nKNOWN FALSE-POSITIVE PATTERNS (avoid repeating these mistakes):\n"
            + "\n".join(patterns[-20:]))


def _record_fp(data_dir: Path, pattern: str, lesson: str) -> None:
    fp_file = data_dir / "fp_memory.jsonl"
    with open(fp_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({"pattern": pattern, "lesson": lesson}, ensure_ascii=False) + "\n")


def _parse_verdict(text: str) -> dict | None:
    t = text.strip()
    if "```" in t:
        # 코드펜스 안의 JSON 추출
        parts = t.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                t = p
                break
    # 마지막 { ... } 블록 탐색
    start = t.rfind("{")
    end = t.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError:
        return None


def investigate(
    seed: dict,
    toolbox: ToolBox,
    provider: Provider,
    data_dir: Path,
    model: str = TRIAGE_MODEL,
    max_turns: int = MAX_TURNS,
    verbose: bool = True,
    package: str = "",
) -> dict:
    """
    하나의 seed를 조사한다.
    seed: {"entry_name", "sink_name", "sink_kind", "path", "missing_guards", ...}
    반환: verdict dict
    """
    fp_memory = _load_fp_memory(data_dir)
    system = _SYSTEM + fp_memory

    # 시작 컨텍스트
    if seed.get("source") == "intent":
        pkg_hint = f"import {package.replace('-', '_')}" if package else "import the package"
        seed_desc = (
            f"## Security-decision function to investigate\n"
            f"Function: {seed.get('entry_name','?')}\n"
            f"File: {seed.get('file','?')}:{seed.get('start_line','?')}\n"
            f"Returns a decision (bool/judgment): {seed.get('returns_bool', False)}\n"
            f"Public API: {seed.get('is_public_api', False)}\n"
            f"Why flagged: {seed.get('intent_signals', [])}\n\n"
            f"This function makes a security judgment. Determine whether its intent\n"
            f"can be violated by crafted input. To PoC, `{pkg_hint}` and call the real function.\n\n"
            f"Begin with read_function('{seed.get('entry_name','?')}')."
        )
    else:
        seed_desc = (
            f"## Starting point\n"
            f"Entry function: {seed.get('entry_name','?')}\n"
            f"Reaches sink: {seed.get('sink_name','?')} [{seed.get('sink_kind','')}]\n"
            f"Call path: {' -> '.join(seed.get('path', []))}\n"
        )
        if seed.get("missing_guards"):
            seed_desc += (
                f"\nASYMMETRY HINT (from static analysis):\n"
                f"Sibling paths to the same sink use these guards that THIS path lacks: "
                f"{seed['missing_guards']}\n"
                f"(e.g. sibling entry '{seed.get('sibling_entry','?')}' has them)\n"
            )
        seed_desc += "\nBegin your investigation. Use read_function to start."

    messages = [{"role": "user", "content": seed_desc}]

    for turn in range(max_turns):
        # 마지막 2턴: 도구 차단하고 판정 강제
        force_verdict = turn >= max_turns - 2
        try:
            if force_verdict:
                # 도구 없이 호출 → 반드시 텍스트(판정)로 응답
                messages.append({
                    "role": "user",
                    "content": ("Stop investigating. Output your final verdict NOW as pure JSON "
                                "(no code fences, no extra text). "
                                "Remember: if the sink is injection-type and you found no sanitizer "
                                "and did not run a PoC, you MUST use 'likely' (not 'not_vulnerable')."),
                })
                result = provider.chat(
                    model=model, messages=messages, system=system, max_tokens=1024,
                )
                verdict = _parse_verdict(result["content"])
                if verbose and verdict:
                    print(f"      판정(강제): {verdict.get('verdict','?')} "
                          f"(conf {verdict.get('confidence','?')})")
                # 파싱 실패 시 음성이 아니라 'likely'로 에스컬레이션 (거짓음성 방지)
                return verdict or {"verdict": "likely",
                                   "vuln_class": "unknown",
                                   "reasoning": "agent could not finalize verdict; escalating",
                                   "confidence": 0.5}

            result = provider.chat_tools(
                model=model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                system=system,
                max_tokens=2048,
            )
        except BudgetExceededError:
            raise

        # assistant 메시지 추가
        messages.append({"role": "assistant", "content": result["raw_content"]})

        if result["tool_calls"]:
            # 도구 실행 후 결과 반환
            tool_results = []
            for call in result["tool_calls"]:
                if verbose:
                    arg_preview = json.dumps(call["input"], ensure_ascii=False)[:80]
                    print(f"      turn {turn+1}: {call['name']}({arg_preview})")
                output = toolbox.dispatch(call["name"], call["input"])
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": call["id"],
                    "content": output[:6000],
                })
            messages.append({"role": "user", "content": tool_results})
            continue

        # 도구 호출 없음 → 최종 판정
        verdict = _parse_verdict(result["text"])
        if verdict:
            if verbose:
                print(f"      판정: {verdict.get('verdict','?')} "
                      f"(conf {verdict.get('confidence','?')}) - {verdict.get('vuln_class','')}")
            return verdict
        else:
            # 판정 형식이 아니면 한 번 더 유도
            messages.append({
                "role": "user",
                "content": "Output your final verdict now in the exact JSON format specified.",
            })

    return {"verdict": "not_vulnerable", "reasoning": "max turns reached without verdict",
            "confidence": 0.0}


def run_agent_investigation(
    seeds: list[dict],
    db_path: str | Path,
    repo_path: str | Path,
    package: str,
    provider: Provider,
    data_dir: str | Path,
    max_seeds: int = 30,
    triage_model: str = TRIAGE_MODEL,
    deep_model: str = DEEP_MODEL,
    verbose: bool = True,
) -> Path:
    """
    여러 seed를 에이전트로 조사.
    1차: triage_model(저가)로 전체 조사
    2차: 'likely'/'confirmed' 만 deep_model(고가)로 재조사
    """
    data_dir = Path(data_dir)
    toolbox = ToolBox(db_path, repo_path, package)

    seeds = seeds[:max_seeds]
    confirmed = []
    triaged = []

    # ── 1차: Haiku triage ─────────────────────────────────────────────────
    print(f"\n  [1차 triage - {triage_model}] {len(seeds)}개 seed 조사")
    for i, seed in enumerate(seeds, 1):
        print(f"    [{i}/{len(seeds)}] {seed.get('entry_name','?')} -> {seed.get('sink_name','?')}")
        try:
            verdict = investigate(seed, toolbox, provider, data_dir,
                                  model=triage_model, verbose=verbose, package=package,
                                  max_turns=TRIAGE_MAX_TURNS)
        except BudgetExceededError:
            print("    예산 초과 - triage 중단")
            break
        verdict["_seed"] = seed
        triaged.append(verdict)

    # Haiku triage가 confirmed(PoC증명) 또는 likely(의심)로 표시한 것을
    # 모두 "게이트 후보"로 넘긴다. Opus는 악용성 게이트에서 단 한 번만 돈다.
    # (이전엔 Opus 2차 심층 + 게이트로 두 번 돌아 예산 초과 → 통합)
    candidates = [t for t in triaged
                  if t.get("verdict") in ("confirmed", "likely")
                  and float(t.get("confidence", 0)) >= 0.5]
    # not_vulnerable은 거짓양성 메모리에 기록
    for t in triaged:
        if t.get("verdict") == "not_vulnerable":
            s = t.get("_seed", {})
            _record_fp(data_dir,
                       pattern=f"{s.get('sink_kind','')} via {s.get('entry_name','')}",
                       lesson=t.get("reasoning", "")[:200])

    # ── 저장 ──────────────────────────────────────────────────────────────
    out_path = data_dir / "agent_confirmed.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    triage_path = data_dir / "agent_triage.jsonl"
    with open(triage_path, "w", encoding="utf-8") as f:
        for t in triaged:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")

    n_conf = sum(1 for t in candidates if t.get("verdict") == "confirmed")
    n_likely = sum(1 for t in candidates if t.get("verdict") == "likely")
    print(f"\n  triage: {len(triaged)} | 게이트 후보: {len(candidates)} "
          f"(confirmed {n_conf}, likely {n_likely})")
    print(f"  {provider.summary()}")
    return candidates
