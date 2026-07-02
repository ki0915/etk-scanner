# AI Pentester — 개발 가이드

## 환경 설정

```bash
# 의존성 설치
pip install anthropic

# API 키 설정 (필수)
export ANTHROPIC_API_KEY="sk-ant-..."   # Windows: $env:ANTHROPIC_API_KEY="..."

# 선택적 모델 오버라이드
export SCREEN_MODEL="claude-haiku-4-5-20251001"
export VALIDATE_MODEL="claude-sonnet-4-6"
export SCREEN_THRESHOLD="6.0"          # 0~10, 기본값 6.0
```

---

## 파이프라인 실행

### 기본 사용법

```bash
# 1. 후보 등록
python scripts/tracker.py new piccolo https://github.com/piccolo-orm/piccolo pypi

# 2. 소스 클론
git clone https://github.com/piccolo-orm/piccolo candidates/ETK-CAND-0001-piccolo/repo

# 3. 파이프라인 실행
python scripts/analyze.py ETK-CAND-0001 piccolo

# 4. 리포트 저장
python scripts/analyze.py ETK-CAND-0001 piccolo --output reports/2025/004/piccolo-auto.md
```

### 단계별 옵션

```bash
# 스크리닝만 (Validator 생략 — 비용 절감, 빠른 탐색)
python scripts/analyze.py ETK-CAND-0001 piccolo --screen-only

# threshold 낮추기 (더 많은 가설 → 더 많은 비용)
python scripts/analyze.py ETK-CAND-0001 piccolo --threshold 4.0

# 심각도 필터 (High 이상만 리포트)
python scripts/analyze.py ETK-CAND-0001 piccolo --min-severity high

# 특정 repo 경로 지정
python scripts/analyze.py ETK-CAND-0006 datasette --repo candidates/ETK-CAND-0006/repo
```

---

## 파이프라인 내부 동작 상세

### Stage 1: Chunker

```python
from pipeline.chunker import chunk_repo
chunks = chunk_repo("candidates/ETK-CAND-0001/repo")
print(f"{len(chunks)} chunks")
# 각 청크: CodeChunk(file_path, name, code, start_line, end_line, context)
```

**청킹 품질 확인**:
- `chunk.to_prompt_block()` — LLM에 전달되는 실제 텍스트 확인
- 너무 작은 청크(< 5줄)는 자동 제외
- 너무 큰 파일(> 500KB)은 라인 윈도우로 fallback

### Stage 2: Screener

```python
from pipeline.screener import screen_chunks
candidates = screen_chunks(chunks, verbose=True)
# 출력: [(confidence, vuln_type, location)]
```

**Screener 프롬프트 튜닝**:
- [scripts/pipeline/screener.py](../scripts/pipeline/screener.py) 의 `_SYSTEM_PROMPT` 수정
- confidence calibration: 모델이 과도하게 높게/낮게 주면 threshold 조정

### Stage 3: Validator

```python
from pipeline.validator import validate_hypotheses
results = validate_hypotheses(candidates, verbose=True)
for r in results:
    if r.confirmed:
        print(r.to_markdown())
```

---

## 새로운 취약점 카테고리 추가

`pipeline/models.py`의 `VulnType` enum에 추가:
```python
class VulnType(str, Enum):
    ...
    MY_NEW_TYPE = "My New Vulnerability Type"
```

Screener 프롬프트에 해당 카테고리 설명 추가 (`_SYSTEM_PROMPT` 내 CWE 목록).

---

## 고비용 경고

| 동작 | 비용 수준 | 권장 사항 |
|------|-----------|-----------|
| `--screen-only` | 저렴 | 탐색 단계에서 사용 |
| 전체 파이프라인 | 중간 | 유망한 패키지에만 실행 |
| threshold 낮추기 | 높음 | 필요할 때만 |
| 큰 모노레포 (> 10만 줄) | 매우 높음 | `--repo` 로 하위 디렉토리 지정 |

**비용 추정** (기준: Python 패키지 5000줄):
- 청크 수: ~150개
- Screener 비용: ~0.002 USD (Haiku, 150 × ~200 토큰)
- 후보 (6%): ~9개
- Validator 비용: ~0.05 USD (Sonnet, 9 × ~1500 토큰)
- **총 비용: ~0.05 USD/패키지**

---

## 개선 로드맵

### 단기 (다음 패키지 분석 전)
- [ ] `chunker.py`에 JS/TS AST 지원 추가 (tree-sitter 또는 esprima)
- [ ] NVD API 연동으로 중복 CVE 자동 확인
- [ ] screener 결과를 `00_analysis.md`에 자동 기록

### 중기
- [ ] 앙상블 스크리닝 (Haiku + Gemini Flash 투표 → 교집합만 통과)
- [ ] Docker 기반 PoC 자동 실행 및 결과 캡처
- [ ] GitHub Security Advisory 초안 자동 생성

### 장기
- [ ] 패키지별 공격 표면 그래프 (AST call graph 기반)
- [ ] 이전 CVE 패턴에서 fine-tuning된 전용 스크리닝 모델

---

## 트러블슈팅

### `ModuleNotFoundError: No module named 'pipeline'`
```bash
# scripts/ 디렉토리에서 실행하거나:
cd Ai_Pentester
python scripts/analyze.py ...
```

### Screener가 모든 청크에 0점 줌
- threshold를 4.0으로 낮춰서 테스트
- `_SYSTEM_PROMPT`에 "Be aggressive in finding issues" 추가

### Validator가 항상 false positive 반환
- 청크 컨텍스트 부족 가능성 → `IMPORT_CONTEXT_LINES` 늘리기 (chunker.py)
- hypothesis description이 너무 모호 → screener 프롬프트 개선

### Rate limit 오류
- `MAX_RETRIES` 및 `RETRY_DELAY` 조정 (screener.py, validator.py)
- 청크를 배치로 처리하는 로직 추가 예정

---

## 기존 수동 워크플로우와의 관계

파이프라인은 **Phase 2 (분석)을 자동화**하는 도구입니다.
수동 분석($analysis)을 대체하는 것이 아니라 1차 스크리닝을 위임합니다.

```
기존: $search → [수동 분석] → $verify → $generate-report
신규: $search → [pipeline] → 고신뢰 후보만 수동 검토 → $verify → $generate-report
```

파이프라인이 GO 판정한 후보는 `candidates/ETK-CAND-XXXX/00_analysis.md`에 기록 후
기존 `$verify` → `$generate-report` 흐름을 그대로 따릅니다.
