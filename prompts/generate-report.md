# $generate-report — CVE 리포트 생성

## 파일명 규칙
`{package-name}-report.md`

## 리포트 구조

```markdown
# {Package Name} 취약점 분석 리포트

| 항목 | 내용 |
|------|------|
| 작성 시간 | YYYY-MM-DD HH:MM KST |
| CVSS 4.0 Score | X.X (Critical / High / Medium / Low) |
| 주간 다운로드 수 | X,XXX,XXX (pypi/npm 기준) |
| 취약점 타입 | [CWE-XXX] 취약점 이름 |
| 대상 버전 | <= X.X.X |
| 패키지 URL | https://... |
| GitHub | https://github.com/... |

---

## 요약 (Summary)

[2~3문장으로 취약점의 핵심을 설명]

## 취약점 설명

[취약점이 무엇인지, 어느 코드에서 발생하는지 상세 설명]

### 취약한 코드

```language
// 파일명:줄번호
<취약한 코드 스니펫>
```

## 근본 원인 (Root Cause)

[왜 이 취약점이 발생하는지 기술적 설명]

## 공격 시나리오

[공격자가 이 취약점을 어떻게 악용할 수 있는지]

## PoC (Proof of Concept)

```python
# 실행 환경: Python X.X, {package}==X.X.X
<PoC 코드>
```

**예상 결과:**
```
<실행 결과>
```

## 영향도

- **기밀성(Confidentiality)**: None / Low / High
- **무결성(Integrity)**: None / Low / High  
- **가용성(Availability)**: None / Low / High

## 수정 방안 (Remediation)

[패치 방법 제안]

## 타임라인

| 날짜 | 내용 |
|------|------|
| YYYY-MM-DD | 취약점 발견 |
| YYYY-MM-DD | maintainer 제보 |
| YYYY-MM-DD | 응답 수신 |
```

## CVSS 4.0 계산 참고

- AV (Attack Vector): N(Network) / A(Adjacent) / L(Local) / P(Physical)
- AC (Attack Complexity): L(Low) / H(High)
- AT (Attack Requirements): N(None) / P(Present)
- PR (Privileges Required): N / L / H
- UI (User Interaction): N / P / A
