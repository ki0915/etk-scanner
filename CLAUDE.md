# AI Pentester - CVE 취약점 발굴 프로젝트

OWASP Seoul Chapter 발표 (김태범 @ Cremit) 기반 AI 협업 취약점 연구 프로젝트.

## 프로젝트 구조

```
Ai_Pentester/
├── candidates/          # ETK-CAND-XXXX 후보 패키지별 폴더
│   └── ETK-CAND-0001-<package>/
│       ├── repo/            # git clone 된 소스
│       ├── vuln-001/        # 발견된 취약점별 폴더
│       ├── 00_search.md     # 탐색 결과
│       └── 00_analysis.md   # 분석 결과
├── reports/             # 최종 CVE 리포트 (YYYY/NNN 형태)
├── scripts/             # 자동화 파이프라인 스크립트
├── prompts/             # 재사용 프롬프트 템플릿
└── artifacts/           # PoC 코드, 증거 파일
```

## 워크플로우

### Phase 1: 대상 탐색 ($search)
- pypi/npm 유명 패키지 중 분석 대상 선정
- 기준: 주간 다운로드 수, GitHub Stars, 패키지 타입
- `scripts/tracker.py`로 중복 제거 및 ETK-CAND 번호 부여

### Phase 2: 분석 ($analysis)
- `git clone`으로 소스 로컬 수집
- 공격 표면 식별 → 취약점 탐색 → 1차 Go-Stop 리뷰
- prompts/analysis.md 규칙에 따라 분석

### Phase 3: 검증 및 리포트 ($verify → $generate-report)
- PoC 생성 및 동작 검증
- Devil's Advocate 반박 검토
- {package-name}-report.md 최종 리포트 작성

## 리포트 헤더 형식

```markdown
| 항목 | 내용 |
|------|------|
| 작성 시간 | YYYY-MM-DD HH:MM |
| CVSS 4.0 Score | X.X (Critical/High/Medium) |
| 주간 다운로드 수 | X,XXX,XXX |
| 취약점 타입 | SQL Injection / RCE / ... |
```

## 분석 원칙

- 패키지 소스를 직접 읽고 모든 유형의 취약점을 자유롭게 탐색
- 특정 함수 grep에 의존하지 않고 코드의 의미를 이해하여 버그를 찾음
- Go-Stop 없이 끝까지 코드를 읽고 판단 (분석은 10분 내로)
- 취약점 발견 후 반드시 DA(Devil's Advocate) 반박 검토 수행

## 분석 흐름

1. 소스 획득 + 구조 파악
2. 공격 표면 식별 (외부 입력점)
3. 코드 통독 + 취약점 탐색
4. 발견 사항 검증 (실제 도달 가능? exploit 가능?)
5. 결과 기록
