"""
provider.py — Anthropic API 래퍼 + 토큰/비용 회계

모든 LLM 호출은 이 모듈을 통과한다.
- 호출마다 (model, in_tok, out_tok, cost_krw) 를 metrics.json에 누적
- 예산 80% → 경고, 100% → BudgetExceededError
- prompt caching, batch API 지원
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import anthropic
import yaml

# ── 설정 로드 ────────────────────────────────────────────────────────────────

def _load_budget(config_path: str | Path | None = None) -> dict:
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "budget.yaml"
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class CallRecord:
    timestamp: str
    model: str
    stage: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float
    cost_krw: float
    is_batch: bool = False


@dataclass
class Metrics:
    records: list[CallRecord] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_cost_krw: float = 0.0

    def add(self, record: CallRecord) -> None:
        self.records.append(record)
        self.total_cost_usd += record.cost_usd
        self.total_cost_krw += record.cost_krw

    def to_dict(self) -> dict:
        return {
            "total_cost_usd": round(self.total_cost_usd, 6),
            "total_cost_krw": round(self.total_cost_krw, 2),
            "call_count": len(self.records),
            "records": [asdict(r) for r in self.records],
        }


# ── 예외 ─────────────────────────────────────────────────────────────────────

class BudgetExceededError(Exception):
    def __init__(self, spent_krw: float, limit_krw: float):
        super().__init__(
            f"Budget exceeded: {spent_krw:.0f}원 / {limit_krw:.0f}원"
        )
        self.spent_krw = spent_krw
        self.limit_krw = limit_krw


class BudgetWarning(UserWarning):
    pass


# ── Provider ─────────────────────────────────────────────────────────────────

class Provider:
    """
    Anthropic API 래퍼.
    모든 chat() / batch_*() 호출이 비용을 추적한다.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        config_path: Optional[str | Path] = None,
        metrics_path: Optional[str | Path] = None,
        stage: str = "unknown",
    ):
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._budget = _load_budget(config_path)
        self._metrics = Metrics()
        self._metrics_path = Path(
            metrics_path
            or Path(__file__).parent.parent.parent / "data" / "metrics.json"
        )
        self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
        self.stage = stage

    # ── 비용 계산 ─────────────────────────────────────────────────────────────

    def _calc_cost(
        self,
        model: str,
        input_tok: int,
        output_tok: int,
        cache_read_tok: int = 0,
        cache_write_tok: int = 0,
        is_batch: bool = False,
    ) -> float:
        """USD 비용 계산."""
        pricing = self._budget["models"].get(model, {})
        factor = self._budget["models"].get(model, {}).get("token_overhead", 1.0)
        discount = pricing.get("batch_discount", 0) if is_batch else 0

        def price(tok: int, rate: float) -> float:
            return tok / 1_000_000 * rate * factor * (1 - discount)

        cost = (
            price(input_tok, pricing.get("input", 3.0))
            + price(output_tok, pricing.get("output", 15.0))
            + price(cache_read_tok, pricing.get("cache_read", 0.0))
            + price(cache_write_tok, pricing.get("cache_write", 0.0))
        )
        return cost

    def _to_krw(self, usd: float) -> float:
        return usd * self._budget.get("krw_per_usd", 1400)

    # ── 예산 체크 ─────────────────────────────────────────────────────────────

    def _check_budget(self, next_cost_krw: float = 0.0) -> None:
        limit = self._budget.get("total_budget_krw", 5000)
        warn_at = limit * self._budget.get("warn_threshold", 0.80)
        spent = self._metrics.total_cost_krw

        if spent + next_cost_krw >= limit:
            self._save_metrics()
            raise BudgetExceededError(spent + next_cost_krw, limit)

        if spent >= warn_at:
            import warnings
            warnings.warn(
                f"[예산 경고] {spent:.0f}원 / {limit:.0f}원 (80% 초과)",
                BudgetWarning,
                stacklevel=3,
            )

    # ── 기록 ─────────────────────────────────────────────────────────────────

    def _record(
        self,
        model: str,
        usage: Any,
        is_batch: bool = False,
    ) -> CallRecord:
        in_tok = getattr(usage, "input_tokens", 0) or 0
        out_tok = getattr(usage, "output_tokens", 0) or 0
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0

        cost_usd = self._calc_cost(model, in_tok, out_tok, cache_read, cache_write, is_batch)
        cost_krw = self._to_krw(cost_usd)

        record = CallRecord(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            model=model,
            stage=self.stage,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            cost_usd=round(cost_usd, 6),
            cost_krw=round(cost_krw, 2),
            is_batch=is_batch,
        )
        self._metrics.add(record)
        self._save_metrics()
        return record

    def _save_metrics(self) -> None:
        self._metrics_path.write_text(
            json.dumps(self._metrics.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── chat() — 동기 단일 호출 ───────────────────────────────────────────────

    def chat(
        self,
        model: str,
        messages: list[dict],
        system: Optional[str | list[dict]] = None,
        max_tokens: int = 2048,
        cache_system: bool = True,
    ) -> dict:
        """
        단일 API 호출. 캐싱 ON이면 시스템 프롬프트를 ephemeral로 마킹.
        반환: {"content": str, "model": str, "record": CallRecord}
        """
        self._check_budget()

        # 시스템 프롬프트 캐싱 처리
        if system:
            if isinstance(system, str) and cache_system:
                system_blocks = [{"type": "text", "text": system,
                                   "cache_control": {"type": "ephemeral"}}]
            elif isinstance(system, list) and cache_system:
                system_blocks = system  # 이미 블록 형태
            else:
                system_blocks = [{"type": "text", "text": system}] if isinstance(system, str) else system
        else:
            system_blocks = None

        MAX_RETRIES = 3
        for attempt in range(MAX_RETRIES):
            try:
                kwargs: dict[str, Any] = dict(
                    model=model,
                    max_tokens=max_tokens,
                    messages=messages,
                )
                if system_blocks:
                    kwargs["system"] = system_blocks

                resp = self._client.messages.create(**kwargs)
                record = self._record(model, resp.usage)
                return {
                    "content": resp.content[0].text,
                    "model": model,
                    "record": record,
                }
            except anthropic.RateLimitError:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(10 * (attempt + 1))
                else:
                    raise

    # ── chat_tools() — tool-use 단일 턴 ───────────────────────────────────────

    def chat_tools(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict],
        system: Optional[str | list[dict]] = None,
        max_tokens: int = 2048,
        cache_system: bool = True,
    ) -> dict:
        """
        tool-use API 단일 턴. 에이전트 루프에서 반복 호출된다.
        반환: {
          "stop_reason": str,        # "tool_use" | "end_turn" | ...
          "text": str,               # 텍스트 블록 합본
          "tool_calls": [{"id","name","input"}],
          "raw_content": [...],      # assistant 메시지에 그대로 넣을 content 블록
        }
        """
        self._check_budget()

        if system:
            if isinstance(system, str) and cache_system:
                system_blocks = [{"type": "text", "text": system,
                                  "cache_control": {"type": "ephemeral"}}]
            elif isinstance(system, list):
                system_blocks = system
            else:
                system_blocks = [{"type": "text", "text": system}]
        else:
            system_blocks = None

        MAX_RETRIES = 3
        for attempt in range(MAX_RETRIES):
            try:
                kwargs: dict[str, Any] = dict(
                    model=model,
                    max_tokens=max_tokens,
                    messages=messages,
                    tools=tools,
                )
                if system_blocks:
                    kwargs["system"] = system_blocks

                resp = self._client.messages.create(**kwargs)
                self._record(model, resp.usage)

                text_parts = []
                tool_calls = []
                raw_content = []
                for block in resp.content:
                    if block.type == "text":
                        text_parts.append(block.text)
                        raw_content.append({"type": "text", "text": block.text})
                    elif block.type == "tool_use":
                        tool_calls.append({
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })
                        raw_content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })

                return {
                    "stop_reason": resp.stop_reason,
                    "text": "\n".join(text_parts),
                    "tool_calls": tool_calls,
                    "raw_content": raw_content,
                }
            except anthropic.RateLimitError:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(10 * (attempt + 1))
                else:
                    raise

    # ── batch_submit() — 배치 제출 ────────────────────────────────────────────

    def batch_submit(self, requests: list[dict]) -> str:
        """
        Haiku 배치 제출. requests는 MessageBatch API 형식.
        반환: batch_id
        """
        self._check_budget()
        batch = self._client.messages.batches.create(requests=requests)
        return batch.id

    def batch_wait(self, batch_id: str, poll_interval: int = 30) -> list[dict]:
        """
        배치 완료까지 폴링. 완료되면 결과 목록 반환.
        """
        while True:
            batch = self._client.messages.batches.retrieve(batch_id)
            if batch.processing_status == "ended":
                break
            time.sleep(poll_interval)

        results = []
        for result in self._client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                msg = result.result.message
                record = self._record(
                    msg.model, msg.usage, is_batch=True
                )
                results.append({
                    "custom_id": result.custom_id,
                    "content": msg.content[0].text,
                    "record": record,
                })
            else:
                results.append({
                    "custom_id": result.custom_id,
                    "content": None,
                    "error": result.result.type,
                })
        return results

    # ── 요약 출력 ─────────────────────────────────────────────────────────────

    def summary(self) -> str:
        limit = self._budget.get("total_budget_krw", 5000)
        spent = self._metrics.total_cost_krw
        over = spent > limit
        status = "[!!] 예산 초과!" if over else "[OK] 예산 내"
        return (
            f"{status} "
            f"{spent:.0f}원 / {limit:.0f}원 "
            f"(${self._metrics.total_cost_usd:.4f}) "
            f"| 호출 {len(self._metrics.records)}회"
        )
