# ETK-Scanner 객관 감사 · 경쟁 분석 · 개선 로드맵

> 목적: 현 프로젝트의 수준을 **과장 없이** 진단하고, 널리 쓰이는 AI 취약점 도구와
> 비교해 부족한 지점을 짚은 뒤, **저비용·고성능 PoC/SAST 도구**로 가기 위한
> 토큰 효율화 방법·아키텍처 선택지·작업 지시서를 정리한다.
> 작성: 2026-10-07 · 대상 범위: 분석 권한이 있는 오픈소스/자체 코드의 **방어적** 취약점 진단과 책임 있는 공개(버그바운티/CVE 리포트).
>
> **이 문서의 사용법**: Part E/F의 "결정 포인트"는 정답을 박아두지 않았다.
> 각 갈림길에 옵션 A/B/C와 trade-off를 적었으니, 구현 중에 사용자가 고르면 된다.

---

## 0. 한 줄 평가

> **"철학과 문서는 상위 10%, 자동화 구현은 하위 50%."**
> 설계 사상(비용을 1급 지표로)과 자기비판적 devlog는 동종 개인 프로젝트 중 매우 우수하다.
> 그러나 **실제로 끝까지 자동으로 도는 파이프라인**은 반쪽이고, README의 수치 주장은
> 코드로 재현되지 않으며, "격리 샌드박스"는 실제로 격리되지 않는다.
> 지금 상태는 **"좋은 뼈대 + 과장된 간판"**. 간판을 내리고 뼈대를 채우면 충분히 경쟁력 있다.

| 축 | 점수(5점) | 근거 |
|---|:---:|---|
| 설계 철학 / 문서화 | ★★★★★ | 비용 1급 지표, `devlog.md`의 정직한 실패 기록(datasette 오판 인정) |
| 정적 분석 엔진 | ★★★☆☆ | Python AST 기반 intent-finder는 견실. JS/TS는 정규식이라 오탐↑, 콜그래프는 이름 기반 휴리스틱 |
| LLM 파이프라인 | ★★☆☆☆ | 티어 캐스케이드 개념은 좋으나 **엔트리포인트 4개 중복**, 고아 모듈 다수 |
| PoC 검증(실행) | ★★☆☆☆ | 실행은 하지만 **격리 없음**(호스트 subprocess). 진짜 Docker 샌드박스는 고아 코드에만 존재 |
| 주장-실제 정합성 | ★☆☆☆☆ | 6.7× 절감·91.7% recall·"격리 샌드박스" 모두 재현/검증 불가 또는 허위 |
| 사용성("토큰만 넣으면") | ★★☆☆☆ | CI 정적 모드는 즉시 되지만, 전체 자동 발견→PoC는 수동 조립 필요 |

---

## Part A — 현 프로젝트 감사 (객관적)

### A.1 실제로 잘 되어 있는 것 (강점)

1. **비용 회계가 진짜 구현됨.** `scripts/pipeline/provider.py`는 호출마다
   `(model, in_tok, out_tok, cache, cost)`를 `metrics.json`에 누적하고, 80% 경고 /
   100% `BudgetExceededError`로 실제 차단한다. 이건 대부분의 경쟁 OSS에도 없는 차별점이다.
2. **"싱크가 아니라 보안 의도 함수를 본다"** (`intent_finder.py`). validate/check/verify/
   is_*/sanitize/parse 등 **판정을 내리는 함수**를 후보로 올리는 발상은 로직 버그(권한/검증 우회)를
   노리는 올바른 방향이고, 업계 최신 흐름(semantic 분석)과 결이 같다.
3. **정적 티어가 토큰 0으로 동작.** `scan.py --mode static` → SARIF 2.1.0 출력 → GitHub Security 탭
   연동 → exit-code 게이트. CI 네이티브 설계는 실무적으로 유용하다.
4. **정직한 devlog.** `datasette` 건을 "CVE가 아니라 일관성 버그였다"고 스스로 뒤집은 기록
   (`docs/devlog.md`)은 신뢰를 준다. 리포트 폴더에도 `DO-NOT-SUBMIT-...` 같은 자기검열 산출물이 있다.
5. **리포트 산출물은 실제로 존재.** `reports/2025/`의 piccolo·datasette(실제 GHSA 제출)·validators
   분석은 사람+에이전트 협업의 진짜 결과물이다.

### A.2 반쪽 구현 · 중복 · 죽은 코드

| 문제 | 증거 | 영향 |
|---|---|---|
| **파이프라인 이원화** | 최상위 `pipeline/`(chunker·taint·context·poc·llm)은 **오직 `run.py`만** import. 실가동 경로는 `scripts/pipeline/`(scan·runner·agent_runner·analyze가 사용) | 어느 게 "진짜"인지 모름. 유지보수 2배 |
| **엔트리포인트 4~5개 중복** | `run.py`(taint 계열) / `scripts/analyze.py`(chunk+orchestrator) / `scripts/runner.py`(7단계 graph→static→haiku→rebut→sonnet→opus_poc) / `scripts/agent_runner.py`(intent→screen→agent→filter→dup→report) / `scripts/scan.py`(CI) | 사용자가 뭘 실행해야 할지 알 수 없음 |
| **`vulnhuntr/` 디렉터리 완전히 비어 있음** | `ls vulnhuntr/` → 파일 0개 | 벤더링 의도만 있고 미구현. 혼동 유발 |
| **candidates 일부 빈 파일** | `ETK-CAND-0001(litellm)`, `ETK-CAND-0011`의 `vulns.json` = 0바이트 | 자동 저장이 끝까지 안 돈 흔적 |
| **Windows 절대경로 박제** | `candidates/.tracker.json`의 `folder: "C:\\Users\\기민수\\..."` | 리눅스/CI에서 경로 해석 불가 → 이식성 0 |
| **backend/ · worker/ · docker-compose** | 라우터/모델 scaffolding은 있으나 파이프라인과 미연결(백엔드가 스캔을 호출하지 않음) | "풀스택" 인상만 주고 실체 없음 |

### A.3 결함 · 리스크 (고쳐야 함)

1. **🔴 "격리 샌드박스"가 격리되지 않음 (허위 + 보안 리스크).**
   `scripts/pipeline/agent_tools.py`의 `run_poc` 도구 설명은
   *"Execute ... in an isolated sandbox. No network allowed."* 라고 광고하지만,
   실제 구현(`agent_tools.py:174`)은
   ```python
   subprocess.run([sys.executable, poc_file], ..., cwd=tmpdir, env=env)  # 호스트 파이썬, 격리 X, 네트워크 차단 X
   ```
   즉 **LLM이 생성한 코드를 호스트에서 그대로 실행**한다. 분석 대상이 신뢰할 수 없는 패키지임을
   감안하면 이는 실제 위험이다. 진짜 Docker 샌드박스(`pipeline/poc.py`: pip install → `docker commit` →
   read-only 마운트 실행)는 **고아 파이프라인에만** 있고 실가동 경로에서 호출되지 않는다.
   → **격리 코드는 이미 있으니, 실가동 경로에 연결만 하면 된다.**
2. **🟠 모델 ID 불일치.** 저장소 전체에 `claude-sonnet-4-6`(14회)·`claude-haiku-4-5-20251001`(11)·
   `claude-opus-4-8`(3)·`claude-opus-4-7`(1)이 혼재. `pipeline-spec.md`는 opus-4-7, `budget.yaml`은 opus-4-8,
   `agent_runner.py`는 sonnet-4-6을 하드코딩. 단일 소스(config)에서 주입해야 함.
3. **🟠 예산 수치 3종 혼재.** `budget.yaml=8000원`, `pipeline-spec.md=5000원`, README/PORTFOLIO 실측=750원.
   어느 게 기준인지 불명.
4. **🟠 벤치마크 재현 불가 + 측정 대상 오해 소지.** `scripts/bench_eval.py`는
   `bench_data/SecurityEval/dataset.jsonl`을 요구하는데 **저장소에 데이터셋이 없다**(fresh clone에서 재현 불가).
   더 중요한 건, 이 벤치는 **Haiku에게 코드 조각 하나를 yes/no로 분류**시키는 것이라 — 실제 티어
   캐스케이드 파이프라인 성능이 아니다. "recall 91.7%"는 *단일 모델 분류기*의 수치다(README도 정밀도 미측정은 인정).

### A.4 주장 vs 실제 (README 간판 점검)

| README 주장 | 실제 | 판정 |
|---|---|---|
| "멀티턴 대비 **6.7× 절감**" | 동일 조건 A/B 로그·스크립트 없음. 서사적 추정 | ⚠️ 근거 불충분 |
| "SecurityEval **recall 91.7%**" | 데이터셋 미포함, 단일 스니펫 분류 측정(파이프라인 아님) | ⚠️ 맥락 오도 |
| "**격리 샌드박스**에서 PoC 실증" | 실가동 경로는 호스트 subprocess(격리/네트워크차단 없음) | ❌ 허위 |
| "exploit before/after **실제 HTTP** 증명" | `candidates/wiki-backend/`에 실제 e2e 스크립트 존재 | ✅ 사실(단, 자체 과제 1건) |
| "CI 네이티브 SARIF 게이트" | `scan.py`·workflow 실제 동작 | ✅ 사실 |

> **권고:** README를 "포부"가 아니라 "현재 사실"만 적도록 정리. 과장은 전체 신뢰도를 깎는다.
> 포부는 이 문서(로드맵)로 옮긴다.

---

## Part B — 경쟁 제품/프로젝트 비교

### B.1 비교표

| 도구 | 유형/라이선스 | 취약점 찾는 방식 | LLM 사용 | 실행 검증(PoC) | 토큰·비용 전략 |
|---|---|---|---|:---:|---|
| **ETK(현재)** | OSS(MIT 표방) | 정적 intent 함수 → Haiku 분류 → Sonnet 에이전트 | API 워커(Claude) | 호스트 subprocess(격리X) | 결정론 선필터+티어+예산가드 |
| **vulnhuntr** (protectai) | OSS **AGPL-3.0** | 입력→출력 **콜체인 추적**, 필요한 코드만 반복 요청 | API 워커(Claude/GPT-4o/Ollama) | ✖(추론 위주) | "surgical" 컨텍스트 최소화, XML/CoT/prefill |
| **Semgrep + Assistant** | OSS 엔진 + 상용 AI | **결정론 규칙 엔진**이 광역 스캔 → AI는 **트리아지/오탐필터/수정안**만 | 트리아지 한정(GPT-4) | ✖ | 규칙이 90% 처리, LLM은 결과에만 → 극저비용. 오탐 ~20%↓, 사람 동의 96~97% |
| **CodeQL** (GitHub) | 상용/무료(OSS 대상) | **데이터플로우/taint를 datalog 쿼리**로 | **없음** | ✖ | LLM 0. 대신 쿼리 작성·DB 빌드 비용 |
| **Snyk Code / DeepCode** | 상용 | ML + 심볼릭 하이브리드, 수백만 리포 학습 룰 | 사내 ML | ✖ | 학습된 모델, 추론 저렴 |
| **Copilot Autofix** | 상용 | CodeQL 탐지 → LLM이 **수정 생성** → 재스캔 검증 | 생성 한정 | 재스캔으로 검증 | 탐지는 결정론, LLM은 패치에만 |
| **Big Sleep / Naptime** (Google) | 비공개 연구 | 에이전트 + 최소 도구(코드브라우저·파이썬샌드박스·디버거·리포터) | 프런티어 워커 | ✅ **샌드박스 퍼징/디버깅** | 실제 SQLite 메모리 0-day 발견(세계 최초 공개 사례) |
| **Aardvark / "Codex Security"** (OpenAI) | 상용(프리뷰) | 4단계: 레포 위협모델→커밋스캔→**샌드박스 검증**→Codex 패치 | GPT-5 풀 에이전트 | ✅ 샌드박스 재현 | 커밋 단위 증분 스캔으로 범위 축소 |
| **XBOW** | 상용 | 자율 침투 에이전트 | 프런티어 워커 | ✅(웹 대상) | HackerOne 리더보드 상위권 성과 |
| **CAI** (aliasrobotics) | OSS(비상용 무료) | 에이전트 중심(Agents/Tools/Handoffs/Patterns/Turns/**HITL**), ReAct | 300+ 모델(Ollama 포함) | 도구 실행 | 모델 교체 자유 → 저가/로컬 믹스 |
| **PentestGPT** | OSS | **태스크 트리**로 LLM을 레일 위에 둠 | API 워커 | 수동 | 상태를 외부에서 관리해 토큰 절약 |

출처는 문서 하단 참조.

### B.2 왜 지금의 ETK가 "부족해" 보이나 — 정직한 진단

1. **탐지 깊이: 콜체인 추적이 없다.** vulnhuntr의 핵심은 *입력→싱크까지 함수 체인을 한 칸씩
   따라가며 필요한 코드만 요청*하는 것. ETK는 `callgraph.py`/`pathfinder.py`가 있지만 이름 기반
   휴리스틱이고, 실가동 에이전트(`agent.py`)는 "함수 하나 주고 조사"에 가깝다. devlog 스스로
   *"GREP을 LLM으로 대체한 것에 불과"*라고 적었다 — 이 자기진단이 정확하다.
2. **검증 신뢰성: 격리가 없다.** Big Sleep·Aardvark가 신뢰받는 이유는 **샌드박스에서 실제로
   재현**하기 때문. ETK는 실행은 하나 격리가 없어 "증명"이라 말하기 어렵고 위험하다.
3. **결정론 비중이 낮다.** 가장 성공한 도구(Semgrep·CodeQL·Copilot Autofix)의 공통점은
   **"결정론 엔진이 광역, LLM은 좁은 판단/생성만"**. ETK는 철학은 같다고 말하지만, 실제론 intent 함수
   목록을 전부 LLM에 흘려보내 결정론 비중이 생각보다 낮다(그래프 반증 단계가 실가동 경로에 약함).
4. **단일 언어 깊이.** Python은 AST로 견실하나 JS/TS는 정규식이라 오탐이 많다. 경쟁군은
   tree-sitter/정식 파서 기반.
5. **"토큰만 넣으면" 미완성.** 지금은 사람이 엔트리포인트·대상·시드 수를 조립해야 한다.

### B.3 성공한 도구들의 공통 승리 공식

```
① 결정론 엔진이 광역을 토큰 0으로 훑는다       (Semgrep 규칙 / CodeQL taint / AST)
② LLM은 "좁혀진 후보"에만, 좁은 판단만 한다     (트리아지 · 가설 · 체인추적)
③ 확정은 추론이 아니라 "격리 실행 재현"으로      (Big Sleep · Aardvark 샌드박스)
④ 사람은 루프 안에(HITL), 최종 리포트/패치로 수렴 (Copilot Autofix · CAI HITL)
```
ETK는 ①②의 철학은 맞지만 **②의 결정론 비중과 ③의 격리**가 약하다. 바로 여기가 개선 레버리지다.

---

## Part C — 토큰 효율화: 방법별 분리 분석

> 질문: "로컬 모델을 학습시킬까? Claude/Codex를 워커로 쓸까?" — 둘은 배타적이지 않다.
> 아래는 각 레버의 **효능·비용·소규모 적합성**을 분리해서 정리한 것.

### C.1 결정론적 선필터 (AST·taint·그래프) — **효능 최고, 비용 0**
- **효능:** 광역에서 90%+를 토큰 0으로 제거. 모든 성공 도구의 1단계.
- **한계:** 로직 버그(권한/검증 우회)는 패턴이 없어 놓침 → 그래서 intent-함수 발상이 필요.
- **소규모 적합성:** ★★★★★ (무조건 최대로 투자). tree-sitter 도입이 최고 ROI.

### C.2 소형/로컬 파인튜닝 모델 (Ollama + fine-tune) — **조건부 효능, 함정 많음**
- **증거:** 파인튜닝한 GPT-3.5/CodeLlama가 특정 과제에서 GPT-4를 앞섬(F1 0.61 vs 0.218),
  파인튜닝 비용은 약 **$19~59**로 저렴(arXiv 2401.17010).
- **그러나 결정적 함정:** 이득이 **학습 분포 안에서만** 나타난다. 실세계/새 패키지로 가면
  일반화가 급락한다. 즉 "다양한 미지 취약점 발견"이라는 ETK 목표와 상충.
- **적합 용도:** *분류/트리아지처럼 범위가 좁고 반복적인 단계*의 로컬 대체(=Haiku 자리).
  발견·PoC 같은 창의적 추론에는 부적합.
- **소규모 적합성:** ★★☆☆☆ (학습 데이터 구축·유지가 개인에겐 부담. 단, "무료 로컬 1차 분류기"로는 매력).

### C.3 프런티어 API를 워커로 (Claude / Codex) — **효능 높음, 변동비**
- **효능:** 발견·체인추적·PoC 생성 같은 창의적 단계에서 압도적. 학습·운영 부담 0.
- **비용:** 토큰당 과금 → **컨텍스트 관리가 비용의 전부**. 프롬프트 캐싱·배치 API·필요한 코드만
  요청(vulnhuntr식 surgical)이 핵심.
- **소규모 적합성:** ★★★★★ (ETK가 이미 택한 길. 올바름). Claude를 "판단/생성 워커"로,
  도구는 코드가 제공.

### C.4 멀티에이전트 (역할 분리) — **효능 중, 비용↑**
- **효능:** 탐지/검증/반증/리포트 분리로 품질↑(CAI의 Handoffs 패턴).
- **비용:** 에이전트 간 메시지로 토큰 급증. 소규모엔 과설계.
- **소규모 적합성:** ★★☆☆☆ (단일 에이전트 + 결정론 도구로 충분. 나중에).

### C.5 캐싱·배치·컨텍스트 관리 — **효능 높음, 공짜에 가까움**
- 프롬프트 캐싱(시스템/룰셋/few-shot 분리): 반복 호출 입력비 ~90%↓.
- 배치 API: 1차 분류를 전량 배치 제출 → 50% 할인.
- 증분 스캔(Aardvark식 커밋 단위): 전체가 아니라 **바뀐 코드만** → 범위 자체를 줄임.
- **소규모 적합성:** ★★★★★ (ETK에 provider 훅은 있으나 배치/증분 미활용. 즉시 먹을 열매).

### C.6 토큰 효율 스펙트럼 요약

```
비용 ────────────────────────────────────────────▶ 높음
효능/단계  [결정론 선필터] [로컬 분류기] [캐싱/배치] [프런티어 워커] [멀티에이전트]
투자 우선   ★★★★★          ★★☆          ★★★★★       ★★★★★           ★★
```
**소규모/개인을 위한 결론:** ①결정론 최대화 + ⑤캐싱·배치·증분으로 **범위와 반복비**를 먼저 깎고,
창의적 단계만 ③프런티어 워커(Claude/Codex)에 맡긴다. ②로컬 파인튜닝은 "무료 1차 분류기"로만
**선택적**으로. 멀티에이전트는 보류.

---

## Part D — 우리만의 특색 (차별점 후보)

경쟁군이 비워둔 자리 = 우리가 설 자리.

1. **💰 비용 투명성 (Cost-native).** 호출별 비용·예산 가드가 이미 구현됨. 경쟁 OSS엔 없다.
   "이 스캔에 453원 썼고 상한 1000원"을 리포트 1급 시민으로 → **개인/학생의 CI**라는 틈새 독점.
2. **🧩 "토큰만 넣으면" 1-커맨드 UX.** `ETK_API_KEY=... etk scan <repo>` 하나로 발견→PoC→리포트.
   경쟁군은 설정이 무겁다. 극단적 단순함이 특색이 될 수 있다.
3. **🛡 보안 의도 함수(semantic intent) + 콜체인 융합.** intent-finder(우리 발상)에
   vulnhuntr식 체인 추적을 결합 → 싱크 기반이 놓치는 로직 버그에 특화.
4. **🔁 발견→수정→실증을 한 사이클로.** Copilot Autofix(수정)와 Big Sleep(실증)의 장점을
   **개인용 저비용**으로 합친 포지션.

---

## Part E — 목표 아키텍처 (선택지: 구현 중 결정)

최종 지향: **`토큰 넣기 → 자동 발견 → 격리 PoC → 비용 찍힌 리포트`** 1-커맨드.
아래 갈림길은 사용자가 고른다.

```
[대상 레포] → (D1) 범위 선택 → ① 결정론 광역 스캔(토큰0)
            → ② 후보 좁힘(intent + taint 체인)
            → (D2) 1차 분류기 선택 → ③ 저가/로컬 분류
            → ④ 프런티어 워커 에이전트(코드 도구 + 체인추적)
            → (D3) 검증 격리 수준 선택 → ⑤ 샌드박스 PoC 실행
            → ⑥ 보안영향/중복 필터 → ⑦ 비용·근거 리포트(SARIF+MD)
```

### 결정 포인트

**D1 — 스캔 범위**
- A. 전체 레포(철저, 비쌈) · B. **변경분/커밋 단위 증분**(Aardvark식, 저렴·CI친화 — 추천 기본값) · C. 사용자가 경로 지정

**D2 — 1차 분류기(가장 싼 단계)**
- A. **Claude Haiku**(현행, 간단·안정) · B. **로컬 Ollama 모델**(토큰 0, 품질 변동·셋업 필요) · C. 하이브리드(로컬로 1차, 애매하면 Haiku 승격)

**D3 — PoC 검증 격리 수준**
- A. **Docker 샌드박스**(이미 `pipeline/poc.py`에 있음 — 실가동 경로에 연결만. 추천) ·
  B. subprocess + seccomp/nsjail(도커 없는 환경) · C. 실행 안 함(추론만, 비추천)

**D4 — 워커 모델**
- A. Claude(Anthropic) · B. Codex/GPT · C. 모델 무관 추상화(CAI식 — `provider.py`를 멀티프로바이더로 일반화)

**D5 — 배포 형태**
- A. CLI 1-커맨드(개인) · B. GitHub Action(팀) · C. backend+worker 서비스(지금 scaffolding 활용)

---

## Part F — 로드맵 & 작업 지시서

> 원칙: **먼저 신뢰를 복구**(거짓/중복 제거)하고 → **얇지만 끝까지 도는 수직 파이프**를 만들고 →
> 그 위에 차별점을 쌓는다. 각 작업은 독립 커밋 단위.

### 🔥 Phase 0 — 신뢰 복구 (1~2일, 토큰 거의 0)

| # | 작업 | 수용 기준 |
|---|---|---|
| 0-1 | **run_poc 격리 연결.** `scripts/pipeline/agent_tools.py`의 `run_poc`를 `pipeline/poc.py`의 Docker 샌드박스(또는 docker 부재 시 nsjail/seccomp 폴백)로 교체. 네트워크 차단 실제 적용 | 신뢰 못 할 PoC가 호스트에서 안 돈다. 도구 설명과 구현 일치 |
| 0-2 | **README 정직화.** "6.7×/91.7%/격리 샌드박스" → 재현 가능한 사실만. 미달 주장은 본 로드맵으로 이동 | README의 모든 수치가 저장소 내 스크립트로 재현 가능 |
| 0-3 | **모델 ID 단일화.** 하드코딩 제거, `config/models.yaml` 한 곳에서 주입(screen/verify/poc 역할명으로) | `grep -r claude-` 결과가 config 1곳 + 참조뿐 |
| 0-4 | **예산 수치 통일** (`budget.yaml` 기준 1개). spec/README 동기화 | 예산 언급이 전부 동일 값 |
| 0-5 | **죽은 코드 정리.** 빈 `vulnhuntr/` 삭제, 빈 candidates 정리, `.tracker.json`의 Windows 절대경로 → 상대경로 | fresh clone이 리눅스/CI에서 그대로 동작 |
| 0-6 | **엔트리포인트 단일화.** `run.py`/`analyze.py`/`runner.py`/`agent_runner.py`를 `etk <subcommand>` 하나로 통합(내부는 유지하되 공개 진입점 1개) | `python -m etk --help`에 scan/hunt/report 서브커맨드 |

### 🧱 Phase 1 — "토큰만 넣으면" MVP 수직 파이프 (3~5일)

| # | 작업 | 수용 기준 |
|---|---|---|
| 1-1 | **1-커맨드 UX.** `ETK_API_KEY=... etk hunt <repo> --budget 1000` → 발견→PoC→리포트 한 번에 | 설정 0으로 리포트 1건까지 자동 생성 |
| 1-2 | **콜체인 추적 강화**(vulnhuntr *아이디어* 차용, 코드 복사 금지=AGPL). intent 함수에서 출발해 caller/callee를 따라가며 **필요한 함수만** LLM에 요청 | 에이전트가 "함수 1개"가 아니라 "입력→싱크 경로"를 본다 |
| 1-3 | **결정론 반증 단계 복원.** 경로 중간에 게이트(권한/검증 함수) 있으면 LLM 호출 전에 기각(`graph_rebut`를 실가동 경로에 연결) | Sonnet 진입 건수 = intent 후보의 5% 이하 |
| 1-4 | **캐싱/배치 실적용.** 시스템/룰셋 캐싱 ON, 1차 분류 배치 제출 | `metrics.json`에 cache_read·batch 기록이 실제로 찍힘 |
| 1-5 | **재현 가능한 벤치 동봉.** SecurityEval 로더 스크립트(다운로드 포함) + 안전 샘플셋 추가로 **정밀도도 측정** | `make bench`가 fresh clone에서 recall+precision+cost 출력 |

### 🚀 Phase 2 — 성능/차별화 (1~2주)

| # | 작업 | 수용 기준 |
|---|---|---|
| 2-1 | **tree-sitter 다언어 파서**로 JS/TS 정규식 대체(+Go/Java 확장 기반) | JS/TS 오탐률 측정상 유의하게↓ |
| 2-2 | **증분 스캔**(변경 커밋만) CI 모드 | PR diff만 스캔, 비용이 변경량에 비례 |
| 2-3 | **CVE 패치 diff를 few-shot**으로 분류 정확도 보강 | CWE 정확도(현 37.8%) 개선 측정 |
| 2-4 | **OSV/GHSA 중복체크를 스캔 흐름에 결선**(이미 `dup_check.py` 존재) | 기지 취약점은 리포트 전 자동 제외 |
| 2-5 | **멀티프로바이더 추상화**(선택: D4) — Claude/Codex/Ollama 교체 가능 | `--provider` 플래그로 워커 교체 |

### 🧪 Phase 3 — 선택적 고도화

- 로컬 Ollama "무료 1차 분류기"(D2-C 하이브리드) · 멀티에이전트 역할분리(CAI식 Handoff) ·
  라이브러리↔소비 코드 연결 추적 · 오탐 피드백 메모리.

### "완료"의 정의 (저비용·고성능 PoC/SAST)
1. fresh clone + API 키만으로 `etk hunt`가 리포트까지 자동 생성 ✅
2. PoC가 **격리 환경**에서 실제 재현 ✅
3. 리포트에 **비용**이 1급으로 표시 ✅
4. 벤치가 **recall+precision+cost**를 재현 가능하게 출력 ✅
5. README의 모든 주장이 저장소 내에서 검증 가능 ✅

---

## Part G — 코드 차용 시 라이선스 주의 ⚠️

사용자가 "좋은 프로젝트 코드를 가져와 수정"하길 원했으나, **라이선스가 이를 제약**한다.

| 프로젝트 | 라이선스 | 차용 가능 범위 |
|---|---|---|
| **vulnhuntr** | **AGPL-3.0**(강한 카피레프트) | ❌ 소스 복사 금지(ETK가 AGPL로 전염). ✅ **아이디어/아키텍처는 자유**(저작권 대상 아님) |
| **CAI** | 비상용 무료 라이선스 | ❌ 상용 금지. ✅ 패턴(Handoff/HITL) 참고 |
| **Semgrep 엔진** | LGPL-2.1 | 규칙(registry) 참고 가능, 엔진 링크 조건 확인 |
| **CodeQL** | 쿼리 MIT / 엔진 상용 | 쿼리 로직 참고 가능 |
| **PentestGPT** | MIT/유사 | ✅ 태스크트리 **코드도** 차용 가능(고지 유지) |

> **지침:** "구조·발상은 자유롭게 벤치마킹하되, AGPL/비상용 소스는 복붙하지 않는다."
> 복사가 가능한 건 **MIT/Apache 계열**(PentestGPT 등)뿐. 체인추적은 vulnhuntr를 **다시 구현**한다.
> ETK의 공개 라이선스(현재 MIT 표방)를 먼저 `LICENSE` 파일로 확정할 것.

---

## 출처 (주요)

- vulnhuntr — [GitHub(protectai)](https://github.com/protectai/vulnhuntr) · [Protect AI: first 0-days](https://protectai.com/threat-research/vulnhuntr-first-0-day-vulnerabilities) (AGPL-3.0, Claude/GPT-4o/Ollama, 콜체인 추적)
- Semgrep Assistant — [GA 발표](https://semgrep.dev/blog/2024/assistant-ga-launch) · [AI 노이즈 필터링(96%)](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories)
- Google Project Naptime/Big Sleep — [Project Zero](https://projectzero.google/2024/06/project-naptime.html)
- OpenAI Aardvark → Codex Security — [OpenAI 소개](https://openai.com/index/introducing-aardvark) · [The Hacker News](https://thehackernews.com/2025/10/openai-unveils-aardvark-gpt-5-agent.html)
- CAI (Alias Robotics) — [GitHub](https://github.com/aliasrobotics/CAI) · [arXiv 2504.06017](https://arxiv.org/abs/2504.06017)
- 파인튜닝 소형모델 vs GPT-4 — [arXiv 2401.17010](https://arxiv.org/html/2401.17010v5)
- (내부 근거) `docs/devlog.md`, `scripts/pipeline/agent_tools.py`, `pipeline/poc.py`, `config/budget.yaml`, `candidates/.tracker.json`
