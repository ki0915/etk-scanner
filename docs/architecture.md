# AI Pentester — 시스템 아키텍처

## 개요

오픈소스 패키지의 CVE를 발굴하기 위한 3단계 AI 협업 파이프라인.
비용 효율을 위해 **저렴한 모델(screener)로 후보를 압축하고, 고성능 모델(validator)로만 정밀 검증**한다.

```
소스코드
   │
   ▼
┌─────────────┐
│  1. Chunker │  AST 파싱 → 의미 단위(함수/클래스/메서드)로 분해
└──────┬──────┘
       │  list[CodeChunk]
       ▼
┌─────────────────────────────────┐
│  2. Screener  (Claude Haiku)    │  모든 청크를 저렴하게 스캔
│     → 취약점 가설 + confidence  │  threshold 미만 제거 (~90% 필터)
└──────────────┬──────────────────┘
               │  list[VulnHypothesis]  (confidence >= 6.0)
               ▼
┌─────────────────────────────────┐
│  3. Validator (Claude Sonnet)   │  고신뢰 후보만 정밀 분석
│     → PoC / CVSS / DA review   │  
└──────────────┬──────────────────┘
               │  list[ValidationResult]
               ▼
          PipelineReport
          + Markdown 리포트
```

---

## 디렉토리 구조

```
Ai_Pentester/
├── candidates/                  # ETK-CAND-XXXX 후보
│   └── ETK-CAND-XXXX-<package>/
│       ├── repo/                # git clone 위치
│       ├── vuln-001/            # 발견 취약점별 폴더
│       ├── 00_search.md
│       └── 00_analysis.md
│
├── scripts/
│   ├── analyze.py               # CLI 진입점
│   ├── tracker.py               # ETK-CAND 번호 관리
│   └── pipeline/
│       ├── models.py            # 데이터 클래스 (CodeChunk, VulnHypothesis, ValidationResult)
│       ├── chunker.py           # AST 기반 코드 분해
│       ├── screener.py          # Haiku 스크리닝
│       ├── validator.py         # Sonnet 정밀 검증
│       └── orchestrator.py     # 파이프라인 조율
│
├── reports/                     # 최종 CVE 리포트
│   └── 2025/NNN/
│       └── <package>-report.md
│
├── artifacts/                   # PoC 코드, 증거 파일
├── prompts/                     # 재사용 프롬프트 템플릿
│   ├── search.md
│   ├── analysis.md
│   ├── verify.md
│   └── generate-report.md
└── docs/
    ├── architecture.md          # 이 문서
    └── development.md           # 개발 가이드
```

---

## 데이터 모델

### CodeChunk
```
file_path   : str       # 상대 경로
chunk_type  : str       # "function" | "method" | "class" | "module"
name        : str       # 함수명 또는 클래스.메서드명
code        : str       # 청크 소스코드
start_line  : int
end_line    : int
context     : str       # 임포트 헤더 + 클래스 선언부 (LLM 컨텍스트용)
language    : str       # "python" | "javascript" | ...
```

### VulnHypothesis
```
chunk          : CodeChunk
vuln_type      : str        # "SQL Injection" | "RCE" | ...
description    : str        # 한 줄 요약
confidence     : float      # 0–10 (screener 모델 자체 평가)
location_hint  : str        # "line 42" 또는 함수명
reasoning      : str        # screener의 판단 근거
screener_model : str
```

### ValidationResult
```
hypothesis     : VulnHypothesis
confirmed      : bool
severity       : Severity      # Critical | High | Medium | Low
cvss_score     : float
attack_path    : str
poc_code       : str
da_rebuttal    : str           # Devil's Advocate 반박
da_response    : str           # 반박에 대한 재검토
mitigation     : str
validator_model: str
```

---

## 모델 선택 전략

| 단계 | 모델 | 역할 | 비용 |
|------|------|------|------|
| Screener | `claude-haiku-4-5-20251001` | 빠른 스캐닝, 가설 생성 | 저렴 |
| Validator | `claude-sonnet-4-6` | 정밀 분석, PoC, DA 검토 | 고비용 |

환경변수로 오버라이드 가능:
```bash
SCREEN_MODEL=claude-haiku-4-5-20251001
VALIDATE_MODEL=claude-sonnet-4-6
SCREEN_THRESHOLD=6.0   # 0~10, 이 값 이상만 validator로 전달
```

**비용 절감 원리**: 일반적으로 청크의 ~90%는 threshold 미만으로 필터됩니다.
Validator는 전체 청크의 5~10%만 처리하므로 비용이 크게 절감됩니다.

---

## 청킹 전략

### Python (AST 파싱)
- `ast.parse()`로 함수/메서드/클래스를 추출
- 5줄 미만의 trivial 헬퍼는 제외 (노이즈)
- 메서드는 임포트 컨텍스트 + 클래스 헤더를 함께 포함

### 기타 언어 (라인 윈도우)
- 80줄 단위 슬라이딩 윈도우, 10줄 오버랩
- tree-sitter 통합으로 개선 예정

---

## 프롬프트 캐싱

`cache_control: {"type": "ephemeral"}`을 시스템 프롬프트에 적용.
동일 런 내에서 Screener/Validator 시스템 프롬프트가 캐시되어
반복 API 호출 비용이 약 90% 절감됩니다.

---

## 확장 계획

| 항목 | 현재 | 목표 |
|------|------|------|
| 언어 지원 | Python 우선 | JS/TS, Go, Rust |
| 청킹 | AST + 라인윈도우 | tree-sitter 기반 다언어 |
| 스크리너 | 단일 모델 | 앙상블 (여러 모델 투표) |
| 중복 체크 | 수동 검색 | NVD/GHSA API 자동 조회 |
| PoC 실행 | 수동 | 격리 컨테이너 자동 실행 |
