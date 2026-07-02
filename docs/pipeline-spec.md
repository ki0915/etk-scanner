# 비용 제어형 다단계 취약점 탐지 파이프라인 스펙

## 목적
방어적 보안 분석 도구. 대상은 분석 권한을 가진 오픈소스/자체 코드베이스.
산출물은 "실행으로 검증된 취약점 후보". 거짓 양성을 비싼 LLM 단계 이전에
결정론적 코드로 최대한 걸러낸다.
**핵심 제약: 중간 규모 라이브러리 1회 전체 분석을 5,000원(약 $3.5) 이내.**

---

## 설계 원칙 (위반 금지)

1. 그래프/AST/반증 등 결정론적 판단은 LLM이 아니라 코드로 한다. (토큰 0)
2. LLM 토큰은 Stage 2(Haiku)와 Stage 4(Sonnet→Opus)에만 쓴다.
3. "코드가 X를 한다"와 "X가 보안 사고다"는 다른 명제다. 후자는 Stage 4
   실행 검증으로만 확정한다. 코드 추론만으로 confirmed 판정 금지.
4. 모든 LLM 호출은 비용을 누적 기록하고, 예산 초과가 예상되면 중단한다.

---

## 모델 배정

| 단계 | 모델 | 비용 |
|------|------|------|
| Stage 2 가설 생성 | claude-haiku-4-5 | $1/$5 per MTok |
| Stage 4-1 1차 검증 | claude-sonnet-4-6 | $3/$15 per MTok |
| Stage 4-2 최종+PoC | claude-opus-4-7 | $5/$25 per MTok |

※ Opus는 새 토크나이저로 동일 입력이 최대 35% 더 많은 토큰 → 1.35배 안전계수 적용

---

## 비용 가드레일

- **prompt caching 기본 ON**: 시스템 프롬프트/룰셋/few-shot은 캐시 대상으로 분리
- **batch API 기본 ON**: Stage 2는 전량 배치로 제출
- **토큰 회계**: 호출마다 `(model, in_tok, out_tok, cost)` → `metrics.json` 누적
- 단계별 상한 (`config/budget.yaml` 기본값):
  - `stage2_max_chunks: 600`
  - `stage4_1_max_candidates: 60`
  - `stage4_2_max_candidates: 25`
  - `total_budget_krw: 5000`
- 차단 규칙:
  - 누적비용 80% 도달 → 경고 로깅
  - 100% 도달 → 다음 LLM 호출 직전 중단, 생존 후보 저장
  - Stage 4-1 진입 건수 > Stage 1 후보의 5% → 앞단 필터 누출 신호 → 중단

---

## 아키텍처

```
Stage 0  그래프 구축        (코드)   레포 → call graph + 진입점/게이트 태그
Stage 1  정적 필터          (코드)   N청크 → 후보청크 (candidates.jsonl)
Stage 2  Haiku 가설 생성    (배치)   후보청크 → 구조화 가설 (hypotheses.jsonl)
Stage 3  그래프 반증        (코드)   가설 → 경로에 게이트 있으면 기각 (survivors.jsonl)
Stage 4-1 Sonnet 1차 검증  (LLM)    생존가설 → confirmed_likely/needs_poc/rejected
Stage 4-2 Opus 최종+PoC    (LLM)    Sonnet이 긍정한 것만 → 샌드박스 재현 (confirmed.jsonl)
```

---

## 스테이지별 기준

### Stage 0 — 그래프 구축 (LLM 0)
- tree-sitter로 함수/메서드 노드 + 호출 엣지 추출
- 진입점 태그: HTTP 라우트/핸들러, CLI 엔트리, 이벤트 핸들러
- 게이트 노드 태그: `config/gates.yaml` (권한체크·입력검증 함수)
- 위험 싱크 태그: `config/sinks.yaml` (execute, eval, system, open, pickle 등)
- 파싱 실패 파일: 스킵 + `logs/parse_failures.log`
- 산출물: `graph.db` (sqlite — nodes, edges, tags 테이블)

### Stage 1 — 정적 필터 (LLM 0, 아래 AND 전부 만족)
- 진입점에서 호출 그래프상 도달 가능
- 외부 입력 흐름 존재
- 위험 싱크 1개 이상 포함
- 테스트/목/픽스처 코드가 아님
- 산출물: `candidates.jsonl`

### Stage 2 — Haiku 가설 생성 (배치 + 캐싱)
- 입력: 청크 본문 + 그래프 요약 1줄 (이웃 청크 코드 첨부 금지)
  - 그래프 요약 예: `"reaches sink:ds.execute via entry:facet_GET; gates_on_path:[]"`
- 출력 스키마 (그 외 텍스트 금지, 파싱 실패 시 1회 재시도 후 폐기):

```json
{
  "chunk_id": "string",
  "vuln_class": "CWE-xxx",
  "entrypoint": "어떤 입력이 어디로 들어오는가",
  "sink": "위험 연산 위치",
  "required_gate": "이 경로에 있어야 할 보안 체크",
  "falsification_condition": "이 가설이 참이면 거짓이어야 하는 관찰",
  "min_repro": "최소 재현 시나리오 한 줄",
  "confidence": 0.0
}
```

- 탈락: `confidence < 0.5` 또는 `falsification_condition`이 빈 문자열
- 산출물: `hypotheses.jsonl`

### Stage 3 — 그래프 반증 (LLM 0, 핵심 비용 절약)
- `required_gate`가 진입점→sink 경로에 노드로 존재하는지 `graph.db` 조회
- 존재 → 보호됨 → 기각 (`rejected_by_graph`, 사유 로깅)
- 부재 → 생존 후보
- 산출물: `survivors.jsonl`

### Stage 4-1 — Sonnet 1차 검증
- 입력: 청크 + 진입점→sink 전체 경로 코드 + 가설
- 판정: `{confirmed_likely, needs_poc, rejected}` + 근거
- `rejected` → 종료 (Opus로 안 보냄)
- `confirmed_likely` / `needs_poc` → Stage 4-2 (상한 적용)

### Stage 4-2 — Opus 최종 + PoC 실행
- 격리 샌드박스(네트워크 차단, 임시 FS, 타임아웃)에서만 실행
- PoC 생성 → 실행 → 재현 여부 판정
- 재현 성공 → `confirmed.jsonl`
- 재현 실패 → `false_positive.jsonl` + Stage 2 few-shot 예시 풀 추가

---

## 안전·윤리 제약

- 방어/제보 목적. 익스플로잇 무기화, 외부 타겟 공격 금지
- PoC는 로컬 샌드박스 재현까지만
- 비밀키/토큰은 환경변수, 코드 하드코딩 금지

---

## 구현 순서

각 단계 끝나면 멈추고 확인 요청.

1. **provider 추상화 + 토큰/비용 회계 + `budget.yaml`** — 이후 모든 단계가 의존
2. **Stage 0 그래프 빌더 + `graph.db`** — 작은 샘플 레포로 노드/엣지 확인
3. **Stage 1 정적 필터 + `gates.yaml` / `sinks.yaml`**
4. **Stage 3 그래프 반증** — 코드만으로 검증되므로 Stage 2보다 골격 먼저
5. **Stage 2 Haiku + 배치 + 캐싱 + 스키마 검증**
6. **Stage 4-1 Sonnet, 4-2 Opus + 샌드박스 + 피드백 루프**
7. **가드레일/중단 로직 + diff 모드(`--since <git-ref>`) + metrics 리포트**

---

## 매 단계 시작 전

그 단계의 입출력 계약과 예상 토큰/비용을 한 줄로 요약하고 진행.

## 완료 후 출력

실행 1회당 리포트: 단계별 통과 개수, 누적 비용(원), confirmed 후보 목록,
false_positive 목록과 사유. **5,000원 초과 여부를 맨 위에 표시.**
