# AI Pentester 개발 일지

OWASP Seoul Chapter 발표(김태범 @ Cremit) 기반 AI 협업 취약점 발굴 파이프라인 구축 과정.
코드 변경이 아닌 **고민한 내용과 개선 방향**을 기록합니다.

---

## 2026-05-30

### 프로젝트 시작 — 기본 파이프라인 설계

**목표**: 코드 → 의미 단위 청크 → 저렴한 모델 가설 생성 → 비싼 모델 최종 검증

발표에서 제시한 핵심 아이디어:
- 방대한 코드를 통째로 LLM에 넣으면 컨텍스트 한계 + 비용 문제
- 의미 단위(함수/클래스)로 쪼개서 Haiku로 1차 필터, 통과한 것만 Sonnet으로 검증
- 비용 대비 효율 극대화

**구현**: `chunker.py` (AST 기반) + `screener.py` (Haiku) + `validator.py` (Sonnet) + `orchestrator.py`

---

### 취약점 발굴 — datasette / piccolo / python-multipart

세 패키지를 수동+에이전트 방식으로 분석. 파이프라인은 구조만 있었고 실제로는 Claude Code 세션에서 에이전트가 직접 분석함.

**piccolo (ETK-2025-001)**: `_get_inserted_pk()`에서 f-string SQL 삽입 발견.
- 한계: SQLite < 3.35.0 환경 + tablename이 공격자 제어여야 함 → CVE 가능성 낮음

**python-multipart (ETK-2025-002)**: `UPLOAD_KEEP_FILENAME=True` 시 symlink following.
- 한계: 비기본 설정 + 공격자가 심링크를 사전 배치해야 함 → 위협 모델 약함

**datasette (ETK-2025-003)**: `allow_sql:false` 설정에서 `?_facet=` 파라미터가 SQL 실행을 우회.
- `?_where=`는 403 차단되는데 `?_facet=`는 200 통과 → 코드 불일치 확인
- PoC 실제 실행으로 검증 완료 (`TEST 1~4`)
- GitHub Security Advisory 제출 (GHSA-m5rj-39jf-xqp)

---

### datasette advisory 과정에서 배운 것

처음에 "CVE 확실"로 시작했다가 점점 약점이 드러남:
1. Test 4 (`secret_tokens` 데이터 노출)가 결정적으로 보였지만 — 그 테이블이 원래 접근 가능했기 때문에 "유출"이라고 보기 어려움
2. view-table `allow:false` 설정하면 facet도 같이 막힘 → 진짜 권한 우회가 아님
3. 행 필터 + facet 조합도 필터 유지됨 → 추가 우회 없음

**결론**: `allow_sql:false` + `?_facet=` 불일치는 실제 보안 사고로 이어지는 경로가 없음. CVE보다는 일관성 버그/문서 이슈에 가까움.

**교훈**: 취약점 발견 → PoC → "보안 사고가 실제로 발생하는가" 순서로 검증해야 함. 코드 불일치를 발견했다고 바로 CVE로 연결하면 안 됨.

---

### LiteLLM 파이프라인 첫 실행

`analyze.py`로 LiteLLM 레포 실행 → **58,592 청크** 추출.
- 문제: LiteLLM이 `tests/`, `cookbook/`, `.github/`, `docs/` 등 포함된 모노레포
- 비용 폭증 → 강제 종료

**개선**: `SKIP_DIRS`에 비보안 디렉토리 추가 (`tests`, `cookbook`, `docs`, `.github`, `enterprise` 등)
→ 21,632청크로 감소했으나 여전히 많음

---

## 2026-05-31

### 파이프라인 근본적 문제 발견

사용자의 지적: "OWASP 발표에서 말한 게 구현이 하나도 안 됐네."

현재 파이프라인의 실제 동작:
```
함수 하나 꺼냄 → Haiku: "이 함수 위험해 보여?" → Sonnet: "PoC 짜봐"
```

이건 **GREP을 LLM으로 대체**한 것에 불과함.

발표에서 말한 로직:
```
외부 입력점 식별 → 입력 흐름 추적 → 위험한 싱크까지 경로 → 경로 전체 컨텍스트로 분석
```

**근본적 차이**: 우리는 청크를 독립적으로 봄. 발표에서는 입력→코드→출력의 **흐름**을 봄.

---

### 테인트 기반 파이프라인으로 전환 결정

**고민한 것**:
- 왜 datasette 케이스에서 실패했나? → `facets.py`의 코드 자체는 문제없어 보임. 문제는 `?_facet=` URL 파라미터가 거기 도달하는 경로와 permission check가 없다는 것 → **경로 추적 없이는 발견 불가**
- 청크 단위 분석의 한계: 같은 파일 안의 다른 함수가 sanitize하는지 모름. 호출 체인을 모름.

**결정**: 소스→싱크 경로를 먼저 찾고, 경로 전체를 Haiku에게 보여주는 방식으로 전환

---

### 새로 추가한 컴포넌트

**`surface.py` — 공격 표면 식별**
- 소스: `request.args`, `request.form`, `request.json()`, `sys.argv`, `os.environ`, `input()`
- 싱크: `cursor.execute()`, `subprocess.run()`, `eval()`, `exec()`, `pickle.loads()`, `yaml.load()`, `open()` (쓰기 모드)
- 고민: 단순 패턴 매칭이라 false positive 많을 수 있음. 추후 semantic 분석으로 보강 필요.

**`callgraph.py` — 함수 호출 관계**
- AST로 "함수 A가 함수 B를 호출한다"는 관계를 추출
- 한계: 이름 기반이라 동명 함수가 여러 개면 오탐. 동적 디스패치 추적 불가. 그러나 정적 분석의 시작점으로는 충분.

**`pathfinder.py` — BFS 경로 탐색**
- 소스 함수 → BFS → 싱크 함수까지 닿는 경로 추출
- 최대 깊이 8로 제한 (깊어질수록 noise 증가)
- 중복 경로 제거: 같은 (소스종류, 싱크종류) 조합은 최단 경로 하나만

**`screener.py` 프롬프트 개선**
- 기존: "이 함수에 취약점이 있어 보이냐?"
- 신규: "이 경로에서 공격자 입력이 싱크까지 실제로 닿느냐? sanitize가 어디 있느냐?"
- VulnPath 객체도 받을 수 있도록 확장

**`orchestrator.py` — `run_pipeline_taint()` 추가**
- 기존 `run_pipeline()`은 청크 기반으로 유지 (호환성)
- 신규 `run_pipeline_taint()`는 소스→싱크 경로 기반

---

### 새 파이프라인 한계 인식

현재 구현(`surface.py` + `callgraph.py` + `pathfinder.py`)의 문제:
- 이름 기반 콜그래프라 동명 함수 오탐/누락
- 게이트(권한체크) 노드를 탐지하지 않음 → 경로 중간에 검증 함수가 있어도 모름
- 배치 API / 프롬프트 캐싱 미적용 → 비용 통제 없음
- Stage 간 비용 누적 추적 없음

---

## 2026-05-31 (오후) — 완전한 파이프라인 설계 확정

### 핵심 설계 변경: 비용 제어형 7단계 파이프라인

**목표**: 중간 규모 라이브러리 1회 전체 분석을 5,000원(약 $3.5) 이내

**핵심 원칙 (이전 파이프라인에서 배운 것)**:
1. 그래프/AST/반증 등 결정론적 판단은 LLM이 아니라 코드로 — 토큰 0
2. "코드가 X를 한다"와 "X가 보안 사고다"는 다른 명제 → datasette 케이스에서 고통스럽게 배운 것
3. 실행 검증으로만 confirmed 판정 (코드 추론만으로 CVE 선언 금지)
4. 모든 LLM 호출은 비용 누적 기록 + 예산 초과 시 자동 중단

**모델 배정**:
- Haiku (Stage 2): 가설 생성, 배치 API, 저가
- Sonnet (Stage 4-1): 1차 검증, 중간
- Opus (Stage 4-2): 최종 + PoC 실행, 극소수만

**7단계 구조**:
```
Stage 0  그래프 구축     (코드)   → call graph + 진입점/게이트/싱크 태그
Stage 1  정적 필터       (코드)   → 진입점 도달 가능 + 싱크 포함한 것만
Stage 2  Haiku 가설      (배치)   → 구조화 JSON 가설
Stage 3  그래프 반증     (코드)   → required_gate가 경로에 있으면 기각
Stage 4-1 Sonnet 1차     (LLM)    → confirmed_likely / needs_poc / rejected
Stage 4-2 Opus + PoC     (LLM)    → 샌드박스 실행 재현 확인
```

**핵심 혁신 — Stage 3 그래프 반증**:
기존에 없었던 것. 권한 체크 함수(게이트)가 경로에 있으면 LLM 없이 코드로 기각.
이것이 Sonnet/Opus 호출을 80~90% 줄이는 핵심.

**예산 가드레일**:
- `config/budget.yaml`로 단계별 상한 설정
- 누적 비용 80% → 경고, 100% → 다음 LLM 호출 전 중단
- Stage 4-1 진입 건수 > Stage 1 후보의 5% → 앞단 필터가 새는 것 → 중단

**피드백 루프**:
- false positive가 나오면 사유를 기록하고 Stage 2 few-shot 예시 풀에 추가
- 다음 실행 시 같은 패턴이 Haiku 단계에서 조기 차단됨

---

## 2026-05-31 (저녁) — 7단계 파이프라인 전체 구현

### 구현 배경

기존 `chunker → screener → validator` 구조의 근본적 문제를 인식:
- 청크를 독립적으로 보기 때문에 공격 경로(흐름)를 모름
- Haiku에게 "이 함수 위험해 보여?"라고 묻는 건 GREP의 LLM 대체에 불과
- 게이트(권한 체크 함수)가 경로에 있어도 탐지 불가 → 거짓 양성 폭발

발표에서 말한 로직의 핵심은 **흐름**이었는데, 우리는 **점**만 보고 있었음.

---

### 새 파이프라인 설계 원칙

1. **결정론적 판단은 코드로** — 그래프 탐색, 게이트 체크는 LLM 0토큰
2. **LLM은 판단 불가능한 것만** — Haiku는 "경로에서 입력이 실제로 싱크에 닿는가", Sonnet은 "코드 전체 맥락으로 진짜인가", Opus는 "PoC 만들고 실행해"
3. **예산이 정확도를 강제** — 5,000원 한도가 있으니 앞단에서 최대한 걸러야 함
4. **피드백 루프** — 거짓 양성이 나오면 그 패턴을 Stage 2 few-shot에 추가

---

### 핵심 설계 결정: Stage 3 그래프 반증

가장 중요한 단계. LLM 비용의 80~90%를 절약하는 핵심.

**고민**: Haiku가 "이 경로에 권한 체크가 필요하다"고 하면, 실제로 그 체크가 경로에 있는지 그래프 DB에서 조회해서 LLM 없이 기각.

datasette 케이스로 예시:
- `?_facet= → facet_results() → ds.execute()` 경로
- `required_gate: datasette.allowed` → 경로에 `allowed` 노드가 있는가?
- 없으면 → 생존 → Sonnet으로 전달
- 있으면 → 기각 (보호됨)

이것이 `?_where=`와 `?_facet=`의 차이를 코드 레벨에서 정확히 잡아낼 수 있는 이유.

---

### 구현한 것들

**`config/budget.yaml`**
- 총 예산 5,000원, 단계별 후보 상한 (Haiku 600개, Sonnet 60개, Opus 25개)
- 모델별 정확한 토큰 가격 (배치 50% 할인, Opus 1.35배 안전계수)
- 경고 임계값 80%, 중단 100%

**`config/gates.yaml`**
- 권한 체크 함수 패턴 목록 (datasette.allowed, check_permission, validate 등)
- 이 이름이 경로에 있으면 Stage 3에서 LLM 없이 기각

**`config/sinks.yaml`**
- SQL: execute, raw, query 등
- CMD: system, run, Popen 등
- Eval: eval, exec
- 역직렬화: pickle.loads, yaml.load
- 파일 쓰기: open(w/a/x)

**`provider.py`**
- 모든 API 호출의 단일 진입점
- 호출마다 (model, tokens, cost_krw) → metrics.json 누적
- 예산 80% → 경고, 100% → BudgetExceededError로 즉시 중단
- 프롬프트 캐싱 (ephemeral cache_control) 기본 ON
- 배치 API 제출/폴링 지원

**`graph_builder.py` (Stage 0)**
- AST 파싱으로 노드(함수)/엣지(호출) → SQLite graph.db 저장
- 진입점 태깅: HTTP 라우트 데코레이터, 함수명 prefix로 탐지
- 게이트 태깅: gates.yaml 패턴 매칭
- 싱크 태깅: sinks.yaml 패턴 매칭
- 실제 결과 (datasette): 노드 1,789개 / 엣지 8,019개

**`static_filter.py` (Stage 1)**
- graph.db에서 BFS로 진입점 → 싱크 경로 탐색
- 조건: 진입점 도달 가능 + 싱크 포함 + 테스트 코드 아님
- 상한 적용 (budget.yaml의 stage2_max_chunks)
- 출력: candidates.jsonl (경로 + 양쪽 코드 포함)
- 실제 결과 (datasette): 진입점 38개 → 후보 50개

**`haiku_screen.py` (Stage 2)**
- candidates.jsonl → 배치 API로 Haiku에 전송
- 각 청크에 "entry→sink 경로 전체" 컨텍스트 포함 (기존엔 청크 하나만 봤음)
- 출력 스키마 강제: vuln_class, required_gate, falsification_condition, confidence
- confidence < 0.5 또는 falsification_condition 빈 것 탈락
- 출력: hypotheses.jsonl

**`graph_rebut.py` (Stage 3)**
- hypotheses.jsonl의 required_gate가 graph.db의 경로에 있는지 조회
- 있으면 기각, 없으면 생존
- 기각 이유를 rejected_by_graph.jsonl에 기록
- 출력: survivors.jsonl

**`sonnet_verify.py` (Stage 4-1)**
- survivors.jsonl → Sonnet으로 전송
- 판정: confirmed_likely / needs_poc / rejected
- rejected는 여기서 종료 (Opus로 안 보냄)
- 출력: verified.jsonl

**`opus_poc.py` (Stage 4-2)**
- verified.jsonl 중 긍정 판정만 → Opus에게 PoC 작성 요청
- 네트워크 코드 포함 시 실행 거부 (socket/urllib/requests/httpx import 차단)
- 격리 tempdir + 10초 타임아웃으로 실행
- "VULNERABLE" 출력 여부로 재현 판정
- 거짓 양성 → fp_reason 기록 → 다음 실행 시 few-shot 예시로 활용

**`runner.py`**
- 전체 파이프라인 오케스트레이터
- --stage N 옵션으로 특정 단계까지만 실행 가능
- Stage 3 생존율 > 5% 경고 (앞단 필터 누출 신호)
- 최종 리포트: 예산 초과 여부를 맨 위에, 단계별 통과 수, 확정 취약점 목록

---

### 기존 코드와의 관계

기존 `chunker.py`, `screener.py`, `validator.py`, `surface.py`, `callgraph.py`, `pathfinder.py`는 유지.
새 파이프라인은 `runner.py`로 실행하며 기존 `analyze.py`와 독립적으로 동작.

---

---

## 2026-05-31 (밤) — 첫 실전 테스트: xmltodict + 치명적 결함 발견

### 실행 결과

xmltodict(649줄 단일 파일)를 새 7단계 파이프라인으로 분석:
```
Stage 0  그래프 (21노드, 98엣지)   → 0원
Stage 1  정적필터 (후보 1개)        → 0원
Stage 2  Haiku 가설 (CWE-91)        → 4원
Stage 3  그래프 반증 (생존 1)        → 0원
Stage 4-1 Sonnet (needs_poc)        → 14원 누적
Stage 4-2 Opus PoC (CONFIRMED)      → 148원 누적
총 소요: 26초, 148원 (예산의 3%)
```

**비용 효율은 목표 달성** — 5,000원 예산 대비 148원.

### 그러나 — Stage 4-2가 거짓 양성을 CONFIRMED로 판정

파이프라인은 `unparse({'#comment': 'text--'})` XML comment injection(CWE-91)을
"확정"으로 보고했다. 그러나 **실제 xmltodict로 검증하니 거짓이었다**:
```
xmltodict.unparse({'#comment': 'malicious--text'})
→ ValueError: Comment text cannot contain '--'
```
최신 xmltodict는 `_validate_comment`로 이미 막고 있었다.

### 근본 원인: Opus PoC가 실제 라이브러리를 import하지 않음

Opus가 생성한 PoC를 보니, `import xmltodict`를 하지 않고 **취약한 동작을
자기가 직접 에뮬레이션**하는 `unparse()` 함수를 새로 작성했다:
```python
def emulate_comment_emit(comment_text, output):
    output.write('<!--')
    output.write(comment_text)  # 검증 없이 — 하지만 이건 Opus가 만든 가짜
    output.write('-->')
```
즉 "취약하다고 가정한 코드"를 만들어 실행하니 당연히 "VULNERABLE"이 나왔다.
**대상 라이브러리를 전혀 건드리지 않은 자기충족적 PoC.**

### 교훈 — opus_poc.py의 결함

1. PoC가 **반드시 대상 패키지를 import**하도록 강제해야 한다.
   현재는 "self-contained PoC"를 요구해서 오히려 에뮬레이션을 유도했다.
2. PoC 실행 환경에 대상 레포를 `sys.path`에 넣고, import 여부를 검증해야 한다.
3. import 없는 PoC는 자동 거짓양성 처리해야 한다.

### 수정 방향 (다음 작업)

- `opus_poc.py`: 프롬프트에서 "반드시 `import <package>` 사용" 명시
- PoC 실행 전 AST로 대상 패키지 import 여부 확인, 없으면 거짓양성 처리
- 샌드박스 sys.path에 대상 레포 경로 주입
- 이번 xmltodict 케이스를 false_positive 회귀 테스트로 보관

### 수정 완료 (당일)

`opus_poc.py`를 4가지로 보강:
1. **프롬프트 강화**: "대상 패키지를 reimplement/emulate 하지 말 것. 실제 함수를
   호출해야 하며, 함수가 입력을 거부하면 NOT_REPRODUCED를 출력하라" 명시
2. **import 검증** (`_imports_target`): PoC AST를 분석해 대상 패키지를 실제로
   import하는지 확인. 없으면 `poc_does_not_import_target`로 거짓양성 처리
3. **PYTHONPATH 주입**: 샌드박스 실행 시 대상 레포 경로를 PYTHONPATH에 추가해
   실제 소스를 import하게 함
4. **NOT_REPRODUCED 우선**: 출력에 NOT_REPRODUCED가 있으면 VULNERABLE이 있어도
   재현 실패로 판정

**재검증 결과**: xmltodict CWE-91 케이스를 다시 돌리니
- 이전: CONFIRMED (에뮬레이션 거짓양성)
- 수정 후: **NOT REPRODUCED** (실제 xmltodict가 `ValueError: Comment text cannot contain '--'`로 차단)

파이프라인이 이제 거짓양성을 정확히 걸러낸다. 비용 81원.

### 종합 평가

xmltodict는 결과적으로 취약점 없음(이미 패치됨)이었지만, 이 테스트로
파이프라인의 가장 중요한 결함(자기충족 PoC)을 발견하고 고쳤다. 첫 실전 대상이
"음성"인 게 오히려 검증기의 신뢰성을 시험하는 좋은 케이스였다.

### 의미

비용 통제와 단계별 필터링은 작동했지만, **최종 검증의 신뢰성이 0이면
파이프라인 전체가 무의미**하다. datasette 때 "코드가 X를 한다 ≠ X가 보안
사고다"를 배웠는데, 이번엔 "PoC가 통과했다 ≠ 실제로 취약하다"를 배웠다.
PoC는 반드시 실제 대상에 대해 실행되어야 한다.

---

---

## 2026-05-31 (심야) — 탐색형 에이전트로 전환 (미지 취약점 탐지)

### 전환 배경

정적 룰 기반 파이프라인의 근본 한계 확인:
- **싱크 패턴 매칭은 "알려진 취약점 유형"만 탐지** — 미지의 CVE를 못 찾음
- differential 분석을 정적으로 돌리니 datasette에서 1,028개 노이즈 (이름 기반
  콜그래프의 가짜 형제 관계 + 느슨한 진입점 탐지)
- 정적 룰로 precision을 내려는 시도 자체가 막다른 길

사용자 질문: "정적 룰은 토큰 절감용이었는데, 에이전트를 만들어 학습시키는 게
맞나, 조정이 맞나?"

### 결론: 정적 룰의 역할을 바꾸고, 에이전트를 넣는다

- **"학습(fine-tuning)"은 틀림** — 데이터 없고, 베이스 모델이 이미 코드 추론 잘함
- **"정적 룰 조정"도 막다른 길** — 1,028개가 증명
- **정답: 정적 그래프 = 판정자(X) → 지도(O)**. 판정은 도구 가진 에이전트가.

핵심: 단발 API는 "주어진 청크"만 보고 판단해야 해서 datasette 같은
"옆 경로엔 권한체크가 있는데 여긴 없다"를 원천적으로 못 본다. 에이전트는
`filters.py`를 직접 찾아 읽어서 불일치를 확인할 수 있다.

### 원래 철학(청킹 → 저가 가설 → 고가 검증)과의 관계

발표의 핵심인 2단계 비용 구조는 **그대로 유지**된다:
| 원래 | 에이전트 | |
|------|---------|--|
| 의미 단위 청크 | 그래프 지도 + on-demand 읽기 | 개선(맥락 단절 제거) |
| 저가 모델 가설 | Haiku triage | 유지 |
| 후보만 고가 검증 | 유망한 것만 Opus PoC | 유지 |

바뀐 건 "청킹" → "그래프 지도 + 능동 읽기" 뿐. 비용 절감 의도(전체 코드를
한 번에 안 넣음)는 유지하되, 청킹의 부작용(맥락 단절)만 제거.

### 구현

**`provider.chat_tools()`**: tool-use API 단일 턴. 도구 호출/텍스트 응답 파싱.

**`agent_tools.py`**: 에이전트가 코드를 능동 탐색하는 6개 도구
- read_function / find_callers / find_callees: graph.db 탐색
- grep_repo / read_file: 실제 소스 검색·읽기
- run_poc: 실제 패키지로 PoC 실행 (import 강제 + 네트워크 차단 + PYTHONPATH 주입)

**`agent.py`**: 탐색 루프
- seed(불일치 후보) → 도구로 능동 조사 → JSON verdict
- 시스템 프롬프트에 "asymmetry를 찾아라", "싱크 존재 ≠ 취약점", "PoC는 실제
  패키지를 import" 명시
- 2단계 비용 구조: Haiku triage 전체 → likely/confirmed만 Opus 심층
- 피드백 메모리: 거짓양성 패턴을 fp_memory.jsonl에 누적 → 다음 실행 주입
- 마지막 2턴엔 도구 차단하고 판정 강제 (턴 소진 방지)

**`agent_runner.py`**: 그래프(지도) → 불일치 seed 생성 → 에이전트 조사

### 검증 (xmltodict)

이전 단발 파이프라인: 에뮬레이션 PoC로 거짓 확정 → 수정 후 NOT_REPRODUCED.
에이전트 방식 결과:
```
8턴 능동 탐색 (unparse, _emit, _validate_name 읽고 실제 라인 확인)
→ 판정: not_vulnerable (confidence 0.95)
→ 근거: "_emit이 비주석 키 전부에 _validate_name 검증을 적용. <,>,",=,/ 차단.
        주석 키만 검증 우회하지만 XML name 검증 불필요한 경우라 안전."
비용: 54원, Opus 호출 0회 (유망 0개)
```

에이전트가 코드를 직접 읽고 **정확히 음성 판정** + 그 근거를 코드 레벨로 제시.
단발 API의 에뮬레이션 거짓양성 문제가 구조적으로 해결됨.

### 남은 과제

- 진짜 양성(취약점 있는 패키지)으로 검증 필요 — 아직 음성 케이스만 확인
- 불일치 seed의 노이즈 (1,028개) → 에이전트가 거르지만 비용 발생. 진입점
  탐지 정밀화로 seed 품질을 올리면 비용 더 절감 가능
- 정적 differential을 seed 생성에만 쓰고 판정은 에이전트가 하므로 노이즈는
  비용 문제이지 정확도 문제는 아님

---

---

## 2026-05-31 (심야 2) — 양성 검증 성공 (A/B 테스트)

### 목표: "진짜 취약점을 찾는가" 증명

음성 케이스(패치된 xmltodict)만 확인했었으므로, 양성 케이스가 필요했다.
가장 깔끔한 방법: **같은 패키지의 패치 전 버전**으로 A/B 테스트.
- 패치 후(0.15.x): `_validate_name` 게이트 있음 → 음성이어야 함 (이미 확인)
- 패치 전(0.14.2): 게이트 없음 → 양성이어야 함 (CVE-2025-9375)

0.14.2를 클론해 직접 확인하니 실제 취약: `unparse({'root': {'evil><script>...': 'v'}})`
→ `<script>`가 그대로 주입됨.

### 1차 시도: 에이전트가 거짓음성 (실제 있는 취약점 놓침)

첫 실행에서 에이전트가 8턴 코드만 읽다가 verdict 못 내고 not_vulnerable로 떨어짐.
두 결함 발견:
1. **PoC를 한 번도 안 돌림** — "sanitizer 없네"에서 "그럼 공격해보자"로 못 넘어감
2. **약한 triage(Haiku)가 음성 판정하면 Opus 에스컬레이션이 막혀 거짓음성 확정**
3. 강제 판정이 JSON 파싱 실패 → 음성 기본값으로 떨어짐

### 수정

1. **PoC 강제**: 인젝션류 싱크는 음성 판정 전에 반드시 run_poc.
   "sanitizer 못 찾았으면 그게 신호 → 공격 페이로드로 PoC 돌려라" 명시
2. **recall 우선 triage**: 불확실하면 'likely'로 에스컬레이션(음성 금지).
   파싱 실패해도 'likely'로 (거짓음성 방지)
3. **triage 확정 보존**: Haiku가 PoC로 confirmed하면 그게 증거 → Opus 재조사
   없이 바로 확정. (이전엔 Opus 재조사가 confirmed를 덮어써서 누락 + 1781원 낭비)

### 2차 시도: 성공

```
패치 전 0.14.2:
  turn 1~5: unparse, _emit, _process_namespace 읽기, escape/sanitize grep
  turn 6: run_poc (악성 element name)
  turn 11~12: run_poc (실제 XMLGenerator로 검증)
  → 판정: confirmed (0.95) CWE-91 XML Injection
  → 근거: "unparse가 사용자 제어 dict 키를 XMLGenerator.startElement()에
          검증·이스케이프 없이 직접 전달"
  비용: 75원 (Opus 미사용)
```

### A/B 최종 결과

| 버전 | 게이트 | 에이전트 판정 | 정답 |
|------|--------|--------------|------|
| 0.15.x (패치 후) | `_validate_name` 있음 | not_vulnerable (0.95) | O |
| 0.14.2 (패치 전) | 없음 | CWE-91 확정 (0.95) | O |

거짓양성 0, 거짓음성 0. **"이 파이프라인이 실제 취약점을 찾는다"가 증명됨.**

### 비용 진화

- 1차(버그 있을 때): Opus 재조사로 1,781원
- 2차(수정 후): Haiku가 PoC로 직접 확정, Opus 불필요 → 75원
- 23배 절감. "이미 PoC로 증명됐으면 고가 모델 안 쓴다"가 핵심.

### 증명된 것 / 남은 것

증명됨:
- 실제 패키지로 PoC 실행하는 검증 (에뮬레이션 거짓양성 해결)
- recall 우선 triage + PoC 강제 (코드만 읽는 거짓음성 해결)
- 저가→고가 2단계 비용 구조 (원래 철학 유지)

남은 것:
- 아직 "알려진 CVE 재발견"까지만. 진짜 미지의(미보고) 취약점 발견은 미검증
- seed가 정적 필터 1개에 의존 — 더 많은 진입점/싱크 커버리지 필요
- 불일치(differential) seed가 이 케이스선 0개였음 (단일 진입점이라). 멀티 진입점
  패키지에서 differential의 실효성 검증 필요

---

---

## 2026-05-31 (밤 3) — 분류 기준 전환 + 악용성 게이트 + 자동 리포트

### 문제: 싱크 기반은 로직 버그(미지 CVE)를 구조적으로 못 찾음

validators 첫 실행(싱크 기반): 5,037원 쓰고 0개.
- src/ 레이아웃이라 PoC import 전부 실패
- re.compile을 eval_exec 싱크로 오탐 → 노이즈 seed
- 진짜 버그(ipv4 SSRF 우회)는 bool 반환 로직버그라 **싱크가 없어 seed에 포함조차 안 됨**

사용자 지적: "취약점 자체가 탐지 안 될 정도로 로직이 별로 아니냐"
→ 맞음. 싱크 기반의 근본 한계. 분류 기준을 바꿔야 함.

### 해결 1: 분류 기준 전환 (싱크 → 보안 의도 함수)

`intent_finder.py` 신규. "위험한 곳"이 아니라 "보안 판단을 하는 곳"을 찾는다:
- 이름 패턴 (validate/check/is_/sanitize/parse/allow/private...)
- bool/판정값 반환 (허용·거부 결정)
- 외부 입력 파라미터
- docstring 보안 단어
- 손으로 짠 파싱 (startswith/regex — 표준 재구현 신호)

파일당 2개 제한으로 다양성 확보 + 비용 절감 (card.py 8개 → 2개).
validators에서 `_check_private_ip`가 후보 7위로 진입 (싱크 기반에선 누락됐던 것).

### 해결 2: 에이전트 프롬프트를 "의도 위반 조사"로 전환

"싱크에 입력이 닿나?" → "이 함수의 보안 의도가 깨지나? 표준 라이브러리와 다른가?"
- stdlib 대조를 핵심 기법으로 (ipaddress.is_private vs 손으로 짠 prefix 매칭)
- 음성 판정 전 PoC 필수, 불확실하면 likely로 에스컬레이션

### 해결 3: 악용성 게이트 (기능버그 vs 진짜 취약점)

사용자 지적: "자동화 파이프라인이면 confirmed=CVE여야 하는 거 아니냐"
→ 맞음. "재현됨"과 "신고 가능"은 다름. `exploit_gate.py` 신규.

엄격 심사: 보안 경계를 넘는가? 현실적 악용 시나리오가 있는가?
단순 기능버그/의도된 동작이면 기각. 메인테이너 반박과 반론까지 생성.

### 해결 4: 증명 가능한 자동 리포트

`report_gen.py` 신규. 게이트 통과분에 대해 PoC를 **실제로 재실행해 출력을 박제**.
재현 불가능한 주장 금지. CVSS·CWE·악용시나리오·DA반박·신고체크리스트 포함.

### 결과: 파이프라인이 자율로 진짜 취약점 발견 (수동보다 강한 것)

validators 전체 실행:
```
intent 10 seed → Haiku triage (426원) → 게이트 후보 4개
→ Opus 게이트: 3개 기각(기능버그), 1개 REPORTABLE
→ 리포트 자동 생성
```

**게이트가 통과시킨 발견 — 내가 수동으로 찾은 IPv4 버그보다 강함:**
```
url('http://[::1]/admin', private=False)               → ALLOWED (루프백 통과)
url('http://[::ffff:169.254.169.254]/', private=False) → ALLOWED (메타데이터!)
url('http://127.0.0.1/', private=False)                → blocked (IPv4는 차단)
```
IPv4-mapped IPv6로 IPv4가 막는 메타데이터에 도달 + IPv4/IPv6 불일치.
PoC 실제 실행 출력 박제됨. CWE-918 SSRF allowlist bypass.

게이트가 uri/domain/auth_segment 3개를 "기능버그"로 정확히 기각한 것이 핵심 —
"confirmed ≠ 신고가능"을 자동으로 구분.

### 비용 분석 + 최적화

- Haiku triage: 426원 (쌈)
- Opus 게이트: ~4,000원 (비용의 90% — 범인)
- → 게이트를 Sonnet으로 교체 (Opus 대비 5배 저렴), 패키지당 ~1,000원 목표

### 버그 수정

- report_gen 재현 마커: "VULNERABLE" 문자열만 찾아 ALLOWED 출력 PoC를 오판 →
  "EXIT=0 + 실패신호 없음"으로 재현 성공 판정하도록 수정
- 리포트 요약이 likely finding의 빈 reasoning을 쓰던 것 → 게이트 분석 우선 사용

### 남은 과제

- IPv6 SSRF 발견을 수동 정밀 검증 후 신고 검토 (datasette 교훈: 게이트 통과 ≠ 확정)
- 중복 체크(CVE/GHSA 자동 조회)는 아직 수동 체크리스트
- 비용: Sonnet 게이트로 낮췄으나 여전히 패키지당 1000원 안팎

---

---

## 2026-05-31 (밤 4) — 경쟁 프로젝트 조사 + 재설계 결정

### 배경: 비용 폭증 + 결과 불안정 → 남의 방식을 배우기로

validators 한 패키지에 1만원 넘게 쓰고 결과도 모델마다 들쭉날쭉.
"우리 방식이 틀린 건가" → 검증된 오픈소스 취약점 발굴 프로젝트들을 조사.

### 조사한 프로젝트와 핵심 교훈

| 프로젝트 | 핵심 방식 | 비용/성과 |
|---------|----------|----------|
| OSS-Fuzz-Gen + FalseCrashReducer | 정적분석(Introspector)이 후보 선정, LLM은 드라이버 생성/검증만. 2-agent로 거짓양성 57~65% 제거 | 프로젝트당 ~$43, 2-agent 추가비용 +9% |
| Big Sleep (Project Zero) | variant analysis(패치된 CVE에서 유사 패턴 검색) + 디버거로 PoC 실제 재현 | SQLite CVE-2025-6965 등 실제 발견 |
| XBOW | 값싼 신호로 타겟 스코어링 → Validator가 실제 익스플로잇으로만 confirm | HackerOne #1 |
| CodeQL+Autofix | CodeQL이 탐지, LLM은 수정안 생성만 (역할 분리) | 수정 3~12배 빠름 |
| GitHub Security Lab Taskflow | threat modeling → 가설 → 엄격 audit 캐스케이드. 로직버그 25% 확정률(최고) | 1003→19 캐스케이드 |
| Vulnhuntr | 콜체인 구성 + 2단계 LLM + 신뢰도 점수. **우리와 가장 유사** | 비용 큼(컨텍스트 욱여넣기) — 우리와 같은 함정 |
| GPTScan | 취약점을 (시나리오+속성)으로 분해 → 단일턴 LLM 매칭 → **정적 확인이 거짓양성 2/3 제거** | **1000줄당 $0.01** (압도적) |
| Vul-RAG | LLM은 취약/양성 구분 본질적으로 못함(0.06~0.14). 과거 CVE 지식 RAG로 16~24%p 상승 | Linux 커널 6 CVE |
| Semgrep Assistant | 엔드포인트 enumerate(룰) → 보안함수 탐지 → taint. IDOR LLM단독 22% → 하이브리드 61% | 신규 SAST 60% 자동 트리아지 |

### 핵심 공식 (모든 성공 프로젝트의 공통점)

**"결정론적 도구로 후보를 좁히고 → LLM은 좁은 추론/생성에만 → 실제 실행으로 검증"**

우리가 틀린 것:
1. **멀티턴 에이전트로 발굴까지 시킴** → 비용 폭증의 근본 원인.
   성공 프로젝트는 전부 후보 선정을 정적도구가 함, LLM은 발굴 안 함.
2. **게이트 불안정은 모델 문제가 아니라 컨텍스트 빈곤** (Vul-RAG 증명).
   데이터플로우 경로 + 과거 CVE 지식 주입하면 Sonnet도 안정.
3. **거짓양성**: PoC 실제 실행을 "필수 통과 조건"으로 (Big Sleep/XBOW).
4. **로직버그**: 보안함수를 LLM으로 찾지 말고 룰로 enumerate, "누락"만 LLM 판정.

비용 충격: GPTScan 1000줄당 $0.01 vs 우리 패키지당 수천원. 차이는 멀티턴 남발.

### 재설계 로드맵 (우선순위)

- **P0**: 멀티턴 에이전트를 발굴에서 제거 → GPTScan식 단일턴 분류 (비용 1/5~1/10)
- **P0**: PoC 실행을 게이트 필수 통과 조건으로 승격
- **P1**: 게이트에 stdlib 대조 + 데이터플로우 경로 컨텍스트 주입 → 저가 모델 안정화
- **P1**: 로직버그 별도 트랙 (엔드포인트/권한 enumerate → 누락 판정)
- **P2**: variant analysis 트랙 (패치된 CVE에서 유사 패턴 — 저비용 고확률)

출처: oss-fuzz-gen, FalseCrashReducer(arXiv 2510.02185), Project Zero Big Sleep,
XBOW, GitHub Security Lab, Vulnhuntr, GPTScan(ICSE'24), Vul-RAG(TOSEM), Semgrep Assistant

### 성과 기록: 자동 파이프라인 첫 검증된 발견

validators IPv6 SSRF allowlist bypass (CWE-918):
- `url(x, private=False)`가 IPv4 내부주소는 차단하나 IPv6/IPv4-mapped는 통과
- 파이프라인이 `_check_private_ip`를 보안의도함수로 식별 → 에이전트가 발견
- stdlib(ipaddress) 대조로 모든 주장 검증 완료 (수동 재확인)
- 리포트: reports/candidates/ETK-CAND-0003/validators-ipv6-ssrf-bypass.md
- 단, "private가 보안경계냐"는 메인테이너 반박 가능 → 신고 전 추가 검토 필요

---

---

## 2026-05-31 (밤 5) — 재설계 완성: 비용 1/10 + 기능버그 자동 분리

### 적용한 개선 (조사 교훈 반영)

**P0 — 단일턴 분류 (screen_single.py)**: 발굴 단계를 멀티턴 에이전트 →
단일 API 호출로 전환 (GPTScan 모델). 의도함수당 도구 없이 1콜.

**보안영향 필터 (security_filter.py)**: "진짜 버그"와 "보안 취약점"을 구분.
검증에서 confirmed된 버그를 단일턴으로 재심사 — "공격자가 무엇을 얻나?"가
핵심 질문. 기능버그(checksum 미검증, validation 느슨)는 자동 탈락.

### 새 파이프라인 흐름

```
의도함수 추출(정적,무료) → 단일턴 분류(Haiku) → 상위N 멀티턴 PoC검증(Sonnet)
→ 단일턴 보안영향 필터(Sonnet) → 증명 리포트
```

### validators 검증 결과

```
의도함수 30 → 분류통과 22 → 검증 4 → 확정버그 3 → 보안취약점 1
비용 750원 (이전 5000~10000원, 1/10)
```

확정버그 3개를 보안영향 필터가 정확히 분류:
- _isin_checksum (체크섬 미검증): 기능버그 → 탈락 ("공격자 이득 none")
- uri (검증 느슨): 기능버그 → 탈락
- _check_private_ip (IPv6 SSRF): SECURITY medium → 통과, 리포트 생성

세 버그 모두 수동 검증으로 실재 확인 (cron */60 통과, isin 체크섬 미검증,
ipv6 SSRF 우회 — 거짓양성 0). 필터가 그 중 보안 취약점만 정확히 골라냄.

### 핵심 성과

- **비용**: 패키지당 750원 (목표 달성, GPTScan 수준에 근접)
- **거짓양성**: 분류·검증 단계 0 (3/3 실재 버그), 보안영향 필터가 기능버그 제거
- **안정성**: 단일턴 위주라 모델 흔들림 없음
- **미지 취약점 발견**: 싱크 없는 로직버그(IPv6 SSRF)를 자동 발견 — 원래 목표 달성

### 모듈 구성 (최종)

- intent_finder.py: 보안 의도 함수 추출 (정적)
- screen_single.py: 단일턴 분류 (Haiku)
- agent.py / agent_tools.py: 멀티턴 PoC 검증 (Sonnet, 소수만)
- security_filter.py: 보안영향 필터 (단일턴, 기능버그 분리)
- report_gen.py: 증명 리포트 (PoC 재실행 박제)
- agent_runner.py: 전체 오케스트레이터
- provider.py: API + 비용회계 + 예산 가드레일
- graph_builder.py: 콜그래프 지도 (보조)

### 남은 과제

- 검증 단계 "강제 판정"이 가끔 likely/confirmed를 JSON 없이 떨굼 → 견고화 여지
- 중복 CVE 자동 조회는 여전히 수동 (신고 전 체크리스트)
- IPv6 SSRF는 "private가 보안경계냐" 메인테이너 반박 가능 → 신고 신중

---

---

## 2026-05-31 (밤 6) — validators 신고 철회 + 새 맹점 발견

### 신고 전 중복 확인에서 막힘

validators IPv6 SSRF를 신고하려다 중복 확인에서 두 벽 발견:
1. **기지(旣知)**: open-webui advisory GHSA-4v7r-f4w8-8972 (2026-05-09)가
   validators의 IPv6 private 미구현 + IPv4-mapped 우회를 이미 공개 서술
2. **책임 소재**: 생태계가 "validators는 IPv6 private 미지원(에러 신호), SSRF로
   쓴 앱 책임"으로 정리. open-webui가 자사 CVE로 수용. validators CVE 아님.

→ validators 대상 신고 철회. 리포트에 DO-NOT-REPORT 박제.

### 파이프라인의 새 맹점 (3번째 게이트가 필요)

지금 파이프라인 게이트:
1. 단일턴 분류 — "의심스러운가"
2. 멀티턴 검증 — "진짜 버그인가" (PoC)
3. 보안영향 필터 — "기능버그 vs 보안취약점"

**빠진 것**: "이 취약점의 책임이 이 라이브러리에 있는가, 아니면 잘못 쓴
사용처에 있는가" + "이미 알려졌는가(중복)".

validators 케이스: 3개 게이트 다 통과했지만 — 책임이 라이브러리가 아니라
사용처(open-webui)에 있었고, 이미 알려진 사실이었다. 파이프라인은 "위험한
동작"은 정확히 짚었으나(open-webui CVE가 증거), "누구의 CVE인가"는 판단 못 함.

### 추가해야 할 게이트 (다음 작업)

- **중복 체크 게이트**: 발견을 CVE/GHSA/이슈/타 advisory에 자동 조회.
  validators 케이스는 open-webui advisory에 이미 있었음 → 자동 검색으로 잡혔어야.
- **책임 소재 판정**: "이게 라이브러리 자체 결함인가, 아니면 문서화된 동작을
  오용한 사용처 문제인가"를 판정. 라이브러리가 "지원 안 함"을 신호하면(에러 등)
  사용처 책임일 가능성.

### 교훈

datasette("코드가 X 한다 ≠ 보안사고") → xmltodict("PoC 통과 ≠ 실제 취약")
→ validators("보안 취약점 ≠ 이 라이브러리의 CVE").
매번 게이트를 하나씩 더 배운다. 파이프라인은 "위험 탐지"는 잘하지만
"신고 가능성(중복·책임소재)" 판단이 약하다 — 이게 다음 핵심 과제.

### 현재까지 신고 가능한 진짜 CVE: 0건

- datasette _facet: 제출했으나 약함 (GHSA-m5rj-39jf-xqp)
- validators IPv6: 철회 (기지 + 책임소재)
- 나머지: 기능버그 또는 패치됨

파이프라인 기술은 완성도가 올라갔으나(비용 750원, 자동 발견 작동),
"신고 가능한 신규 CVE"라는 최종 목표물은 아직 0건. 더 나은 타겟 선정 +
중복/책임 게이트가 필요.

---

---

## 2026-06-01 — NVIDIA SkillSpector 조사 + 중복 체크 게이트 추가

### SkillSpector 조사 (우리와 유사 프로젝트)

NVIDIA/SkillSpector: AI 에이전트 skill/MCP의 보안 검사기. 대상은 다르지만
(skill의 prompt injection/tool poisoning vs 우리의 라이브러리 취약점) 철학 동일:
정적 recall → LLM precision.

비교 결과:
- **우리가 앞선 점**: 모델 계층화(Haiku분류→Sonnet검증), 멀티턴 PoC 실증.
  SkillSpector는 단일 모델 + 단일턴 판정으로 끝 (PoC 실행 안 함).
- **우리가 부족한 점**: 중복/기지 체크. SkillSpector는 OSV.dev를 파이프라인에
  통합해 의존성 CVE를 자동 조회. 우리는 이게 없어서 validators 건이 신고 직전까지
  갔다(open-webui advisory에 이미 있던 걸 수동으로야 발견).

배울 것: ① OSV/CVE 자동 조회(중복 체크) ② 정량적 confidence 게이트
③ 의도 분류 축 ④ 컨텍스트 민감 프롬프트 ⑤ overlap 청킹 ⑥ anti-adversarial 가드.

### 결정: 중복 체크 게이트 추가 (최우선)

validators 교훈 + SkillSpector OSV 통합 = "발견을 신고 전 자동으로 기지
여부 조회". 이게 우리 최대 약점("신고 가능성 판단")의 핵심 보강.

---

## 2026-06-01 (2) — 프로젝트 정체성 재정의 + DevSecOps CI 게이트

### 정직한 인정: 신규 CVE 실증 0

- xmltodict = 기존 CVE 재발견(positive control), 신규 아님
- validators = 진짜 버그지만 기지(open-webui) + 책임 사용처
- datasette = 제출했으나 약함
→ "싸게 CVE 찾는다"는 속 빈 주장. 발굴로 자기소개 불가.

### 결정: 발굴 도구 → "비용 인식 스캐너"로 정체성 전환

우리가 실제로 증명한 것 = 엔지니어링:
- 단계별 비용 측정, 예산 가드레일, 오탐 필터, 모델 계층화.
CVE 없어도 오늘 증명 끝난 것.

차별점 = 정확도 축(다 함) 아니라 **비용 축(아무도 안 함)**.
"학생도 돌릴 만큼 싼 LLM 보안 스캐너" = 빈 구멍. 제약이 곧 기여.

### 구현 (A안: DevSecOps CI 게이트) — 오늘 완성

- `pipeline/sarif.py`: findings → SARIF 2.1.0 (GitHub Security 탭)
- `scan.py`: CI 진입점. static(무료)/llm(예산상한) 모드, exit-code 게이트, cost.json
- `.github/workflows/security-scan.yml`: PR→무료정적, 수동→LLM옵션, SARIF 업로드
- README: 정직한 프레이밍 ("cost-aware, not CVE hunter")

검증: validators 정적 스캔 = 69건 0원 0.3초, SARIF 유효(2.1.0), exit-code 게이트 작동.

### 정체성 한 줄

"탐지기 아님 — 비용을 1급 지표로 만든 보안 CI 게이트."
취업 = "취약점 찾았다(운)" 아니라 "비용 인식 보안 파이프라인 만들었다(실력)".

---

## 2026-06-01 (3) — 비용 증명 벤치마크 골격 (bench.py)

### 증명 원칙: 추정 금지, 자기 로그 실측

"동목적보다 토큰 덜 든다"를 증명하려면 같은 입력 → 각 도구의 자기 로그 대조.
- 우리: metrics.json (provider.py가 호출마다 model/토큰/비용 기록)
- Vulnhuntr: 자체 usage 출력 (오픈소스 LLM 취약점 스캐너 = 동목적 대조군)

### bench.py

같은 repo → 우리(scan LLM) + Vulnhuntr 실행 → 각 로그 파싱 → 표
(도구/토큰/비용/발견/시간) + "우리가 N배 적음" 배수. bench_result.json 저장.
--dry로 골격 확인(API 미실행). 크레딧 0이라 수치는 충전 후 채움.

### 현재 상태 = 방법론 완성, 수치 pending

- LLM 검증 감사로그: metrics.json (구조 완성, 실측은 크레딧 필요)
- 대조 벤치마크: bench.py 골격 완성, 충전 즉시 실측
- 정직: "증명 설계 완료, 숫자 pending" — 방법론 자체가 취업 어필

### 오늘 산출물 총정리 (A안 완료)

- scan.py + sarif.py: 무료 정적 CI 스캔 (69건 0원 실측)
- .github/workflows/security-scan.yml: PR 자동 + SARIF 업로드
- bench.py: 비용 대조 벤치마크 골격
- README: cost-aware 정체성
- provider.py: 단계별 비용회계 + 예산 가드레일 (증명 인프라)

### 남은 문제들

1. **callgraph 정확도**: 이름 기반이라 오탐/누락 있음. tree-sitter로 개선 가능.
2. **cross-file taint**: 현재는 같은 파일 내 경로만 잘 추적. 파일 간 경로는 함수 이름으로만 연결.
3. **sanitization 감지**: Haiku가 경로 중간의 sanitize를 얼마나 잘 인식하는지 실전 검증 필요.
4. **비Python 언어**: JS/TS/Go는 여전히 라인윈도우 fallback.
5. **실전 검증 미완**: 새 파이프라인으로 실제 패키지 분석해서 precision/recall 측정 필요.

---

### 향후 개선 방향

- [ ] `datasette`의 `?_facet=` 케이스를 새 파이프라인으로 재현 → 경로가 탐지되는지 확인
- [ ] pyasn1 Long Tag DoS — 기존 CVE(OID)와 동일 패턴이나 Long Tag에는 미적용. PoC 작성 예정.
- [ ] LiteLLM proxy/ 디렉토리만 타겟으로 새 파이프라인 실행
- [ ] precision 측정: 탐지된 경로 중 실제 취약점 비율 추적
