"""
Screener — Stage 2 of the pipeline.

Sends each CodeChunk to a cheap model (default: claude-haiku-4-5)
and asks it to generate vulnerability hypotheses with confidence scores.

Only hypotheses at or above SCREEN_THRESHOLD (default 6/10) are forwarded
to the expensive validator.

Uses prompt caching on the system prompt to minimise token cost when
processing many chunks from the same run.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

import anthropic

from pipeline.models import CodeChunk, VulnHypothesis

SCREEN_MODEL = os.getenv("SCREEN_MODEL", "claude-haiku-4-5-20251001")
SCREEN_THRESHOLD = float(os.getenv("SCREEN_THRESHOLD", "6.0"))
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


_SYSTEM_PROMPT = """\
You are a senior security researcher specialising in source-code vulnerability discovery.

You will receive a TAINT PATH: a chain of function calls from an external input source
(attacker-controlled) to a dangerous sink operation. Your job is to determine whether
attacker-controlled input can actually flow through this path to trigger the sink.

Rules:
- The path shows HOW input travels through the code. Your job is to verify IF it does.
- Check: is the input sanitized or validated anywhere along the path?
- Check: can the attacker actually control the value that reaches the sink?
- Rate confidence based on REACHABILITY, not just code pattern.
  9-10 = input definitely reaches sink unsanitized
  7-8  = likely reaches sink with some effort
  5-6  = possible but there may be guards
  <5   = speculative, guards likely present
- If the path is blocked by validation/sanitization, return empty hypotheses.

Output ONLY valid JSON (no markdown):
{
  "hypotheses": [
    {
      "vuln_type": "<SQL Injection | Command Injection | Path Traversal | RCE | ...>",
      "description": "<one sentence: what input, what sink, what impact>",
      "confidence": <0-10 float>,
      "location_hint": "<sink function:line>",
      "reasoning": "<why attacker input reaches the sink>",
      "sanitization_check": "<any sanitization found, or 'none'>",
      "attack_example": "<concrete example of malicious input>"
    }
  ]
}"""


def _call_screener(
    client: anthropic.Anthropic,
    chunk: "CodeChunk | VulnPath",
) -> list[VulnHypothesis]:
    # VulnPath 지원: 경로 컨텍스트 전체를 프롬프트로 전달
    from pipeline.pathfinder import VulnPath as VP
    if isinstance(chunk, VP):
        prompt_block = chunk.to_prompt_block()
        user_msg = (
            "Analyse this taint path for a security vulnerability.\n"
            "Determine if attacker input from the source can reach the sink unsanitized:\n\n"
            + prompt_block
        )
        # chunk 호환용 더미 CodeChunk 생성
        compat_chunk = CodeChunk(
            file_path=chunk.source.file_path,
            chunk_type="taint_path",
            name=f"{chunk.source.func_name} → {chunk.sink.func_name}",
            code="\n\n".join(chunk.path_code),
            start_line=chunk.source.line,
            end_line=chunk.sink.line,
        )
    else:
        prompt_block = chunk.to_prompt_block()
        user_msg = "Analyse this code chunk for security vulnerabilities:\n\n" + prompt_block
        compat_chunk = chunk

    for attempt in range(MAX_RETRIES):
        try:
            response = client.messages.create(
                model=SCREEN_MODEL,
                max_tokens=1024,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[
                    {
                        "role": "user",
                        "content": user_msg,
                    }
                ],
            )
            break
        except anthropic.RateLimitError:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
            else:
                raise
        except anthropic.APIError as exc:
            raise RuntimeError(f"Screener API error: {exc}") from exc

    raw = response.content[0].text.strip()

    # Strip markdown fences if model added them anyway
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    hypotheses: list[VulnHypothesis] = []
    for h in data.get("hypotheses", []):
        try:
            confidence = float(h.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0.0

        hypotheses.append(
            VulnHypothesis(
                chunk=compat_chunk,
                vuln_type=h.get("vuln_type", "Other"),
                description=h.get("description", ""),
                confidence=confidence,
                location_hint=h.get("location_hint", ""),
                reasoning=h.get("reasoning", ""),
                screener_model=SCREEN_MODEL,
            )
        )

    return hypotheses


def screen_chunks(
    chunks: list[CodeChunk],
    api_key: Optional[str] = None,
    verbose: bool = False,
) -> list[VulnHypothesis]:
    """
    Screen all chunks with the cheap model.
    Returns only hypotheses >= SCREEN_THRESHOLD.
    """
    client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    candidates: list[VulnHypothesis] = []

    for i, chunk in enumerate(chunks, 1):
        if verbose:
            print(f"  [{i}/{len(chunks)}] screening {chunk.name} ({chunk.file_path}:{chunk.start_line})")

        hypotheses = _call_screener(client, chunk)

        for h in hypotheses:
            if h.confidence >= SCREEN_THRESHOLD:
                candidates.append(h)
                if verbose:
                    print(f"    -> [{h.confidence:.1f}] {h.vuln_type}: {h.description[:80]}")

    return candidates
