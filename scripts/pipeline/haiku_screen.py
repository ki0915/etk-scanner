"""
haiku_screen.py — Stage 2: Haiku 가설 생성 (배치 + 캐싱)

candidates.jsonl 의 각 후보를 Haiku에게 보내 구조화 가설을 생성한다.
- 배치 API로 비용 50% 절감
- 시스템 프롬프트 캐싱으로 반복 호출 비용 절감
- 출력 스키마 강제, 파싱 실패 시 1회 재시도 후 폐기
- confidence < 0.5 또는 falsification_condition 빈 것은 탈락
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from pipeline.provider import Provider

_SYSTEM = """\
You are a security researcher. You will receive a code path from an external input (source)
to a dangerous operation (sink). Your job is to generate a structured vulnerability hypothesis.

Rules:
- Only report if attacker-controlled input can plausibly reach the sink unsanitized.
- required_gate: name the specific permission/validation function that SHOULD be on this path.
- falsification_condition: state what observable fact would DISPROVE the hypothesis.
  If you cannot state one, set confidence below 0.5.
- confidence: 0.9+ = near certain. 0.7-0.9 = likely. 0.5-0.7 = possible. <0.5 = skip.

Output ONLY valid JSON, no markdown:
{
  "chunk_id": <integer from input>,
  "vuln_class": "CWE-XXX",
  "entrypoint": "what input enters where",
  "sink": "dangerous operation location",
  "required_gate": "function name that should guard this path",
  "falsification_condition": "observable fact that would disprove this",
  "min_repro": "one-line minimal reproduction scenario",
  "confidence": 0.0
}"""


def _build_user_msg(candidate: dict) -> str:
    path_str = " → ".join(candidate.get("path", []))
    return (
        f"chunk_id: {candidate['chunk_id']}\n"
        f"Entry: {candidate['entry_name']} ({candidate['entry_file']})\n"
        f"Sink: {candidate['sink_name']} [{candidate['sink_kind']}] "
        f"({candidate.get('sink_file','?')}:{candidate.get('sink_line','?')})\n"
        f"Call path: {path_str}\n\n"
        f"Entry code:\n```python\n{candidate.get('entry_code','')[:1500]}\n```\n\n"
        f"Sink code:\n```python\n{candidate.get('code','')[:1500]}\n```"
    )


def _parse_hypothesis(raw: str, chunk_id: int) -> dict | None:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.rsplit("```", 1)[0]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None

    confidence = float(data.get("confidence", 0))
    falsification = data.get("falsification_condition", "").strip()

    if confidence < 0.5 or not falsification:
        return None

    data["chunk_id"] = chunk_id
    data["confidence"] = confidence
    return data


def run_haiku_screen(
    candidates_path: str | Path,
    provider: Provider,
    hypotheses_path: str | Path | None = None,
    max_chunks: int = 600,
    use_batch: bool = True,
) -> Path:
    candidates_path = Path(candidates_path)
    if hypotheses_path is None:
        hypotheses_path = candidates_path.parent / "hypotheses.jsonl"
    hypotheses_path = Path(hypotheses_path)

    # candidates 로드
    candidates = []
    with open(candidates_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                candidates.append(json.loads(line))

    if len(candidates) > max_chunks:
        print(f"  후보 {len(candidates)}개 → 상한 {max_chunks}개로 자름")
        candidates = candidates[:max_chunks]

    model = "claude-haiku-4-5-20251001"
    hypotheses = []

    if use_batch:
        # ── 배치 모드 ──────────────────────────────────────────────────────
        requests = []
        id_map = {}  # custom_id → chunk_id

        for cand in candidates:
            cid = str(uuid.uuid4())
            id_map[cid] = cand["chunk_id"]
            requests.append({
                "custom_id": cid,
                "params": {
                    "model": model,
                    "max_tokens": 512,
                    "system": [{"type": "text", "text": _SYSTEM,
                                "cache_control": {"type": "ephemeral"}}],
                    "messages": [{"role": "user", "content": _build_user_msg(cand)}],
                },
            })

        print(f"  배치 제출: {len(requests)}개 요청")
        batch_id = provider.batch_submit(requests)
        print(f"  batch_id: {batch_id} — 완료 대기 중...")
        results = provider.batch_wait(batch_id)

        for result in results:
            if result.get("content"):
                chunk_id = id_map.get(result["custom_id"], -1)
                hyp = _parse_hypothesis(result["content"], chunk_id)
                if hyp:
                    hypotheses.append(hyp)

    else:
        # ── 동기 모드 (배치 미지원 환경) ──────────────────────────────────
        for i, cand in enumerate(candidates, 1):
            print(f"  [{i}/{len(candidates)}] chunk_id={cand['chunk_id']}")
            resp = provider.chat(
                model=model,
                messages=[{"role": "user", "content": _build_user_msg(cand)}],
                system=_SYSTEM,
                max_tokens=512,
                cache_system=True,
            )
            hyp = _parse_hypothesis(resp["content"], cand["chunk_id"])
            if hyp:
                hypotheses.append(hyp)

    hypotheses_path.parent.mkdir(parents=True, exist_ok=True)
    with open(hypotheses_path, "w", encoding="utf-8") as f:
        for h in hypotheses:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")

    print(f"  후보: {len(candidates)} | 가설 생성: {len(hypotheses)}")
    print(f"  비용: {provider.summary()}")
    return hypotheses_path
