# wiki-backend 보안 감사 — 취약점 발견 · 수정 · 실증

> 개인 프로젝트(TypeScript/Express 백엔드)를 대상으로 인증 취약점을 발견하고,
> 수정한 뒤, **실제 HTTP 서버로 exploit before/after를 실증**한 DevSecOps 사이클.

| 항목 | 내용 |
|------|------|
| 대상 | [ki0915/wiki-backend](https://github.com/ki0915/wiki-backend) (Express + Sequelize + JWT) |
| 감사일 | 2026-06-01 |
| 발견 | 인증 취약점 4건 (CWE-798, CWE-287, CWE-532) |
| 최고 위험 | 하드코딩 JWT 시크릿 → 자격증명 0으로 계정 탈취 |
| 실증 | 실제 HTTP 서버 대상 토큰 위조 (취약: 200 침입 / 수정: 401 차단) |
| 산출 | 수정 커밋 + SARIF + CI 게이트 + Docker 재현 환경 |

---

## 1. 요약 (Executive Summary)

개인 위키 백엔드에서 **하드코딩된 JWT 서명 시크릿**을 발견했다.
시크릿 `'my-secret-key'`가 공개 GitHub 저장소 소스에 그대로 박혀 있어,
누구나 이를 읽어 **임의 사용자의 인증 토큰을 위조**할 수 있었다.

- **영향(CIA):** 기밀성(C) + 무결성(I) 침해. 가용성(A)은 해당 없음.
- **공격 유형:** 인증 우회 / 권한 탈취 (auth bypass)
- **공격자 이득:** 로그인 없이 임의 계정으로 위장 → 보호 API 접근, 타인 글 읽기·수정·삭제

수정 후, 동일한 위조 토큰이 실제 서버에서 거부됨을 HTTP 요청으로 확인했다.

---

## 2. 발견된 취약점

| # | 취약점 | CWE | 심각도 | 파일 |
|---|--------|-----|--------|------|
| 1 | 하드코딩 JWT 시크릿 | CWE-798 → 287 | High | `login.controller.ts:9`, `verify.token.ts:5` |
| 2 | 로그인 쿼리에 평문 password 포함 | CWE-287 | Medium | `login.controller.ts:40` |
| 3 | signUp 중복확인 결함 (평문 password 조건) | - | Medium | `signUp.controller.ts:33` |
| 4 | JWT 토큰을 로그 파일에 기록 | CWE-532 | Low | `login.controller.ts:63` |

### 근본 원인 (취약점 1)
```typescript
// verify.token.ts, login.controller.ts — 시크릿이 소스에 하드코딩
const secretKey = 'my-secret-key';
...
const decoded = jwt.verify(token, secretKey);   // authMiddleware
```
공개 저장소 = 시크릿 공개 = 서명 위조 가능.

---

## 3. 취약점 진단 기준 (방법론)

취약점 여부를 **"공격자가 무엇을 얻는가(attacker gain)"** 로 판정.

| CIA 축 | 침해 여부 | 근거 |
|--------|-----------|------|
| 기밀성 (Confidentiality) | ✅ | 위조 토큰으로 타인 보호 데이터 열람 |
| 무결성 (Integrity) | ✅ | 위조 토큰으로 article 수정/삭제 (`/article/update`, `/delete`) |
| 가용성 (Availability) | ❌ | 서비스 중단과 무관 (DoS 유형 아님) |

→ **권한 탈취(auth bypass)** 로 분류. "기능 버그"가 아니라 보안 경계 침해.

---

## 4. Exploit 실증 (실제 HTTP 서버)

authMiddleware를 격리 실행하여 위조 토큰을 실제 HTTP로 검증.

### 4.1 취약본 (하드코딩 시크릿)
```
$ BRANCH=vuln node e2e_server.js       # 서버 :10000

# 공격자: git에서 읽은 시크릿으로 admin 토큰 위조
$ FORGED=$(jwt.sign({userId:'attacker'}, 'my-secret-key'))

토큰 없이:  HTTP 401
위조 토큰:  HTTP 200 → {"msg":"보호 데이터","user":{"userId":"attacker"}}
```
**→ 자격증명 0으로 보호 라우트 침입 성공.**

### 4.2 수정본 (env 시크릿)
```
$ BRANCH=fixed JWT_SECRET=prod-secret-not-in-git node e2e_server.js

# 공격자는 여전히 유출된 옛 시크릿으로 위조 시도
위조 토큰:  HTTP 401 → {"msg":"토큰 무효"}
```
**→ 유출 시크릿 무효화, 침입 차단.**

| 요청 | 취약본 | 수정본 |
|------|--------|--------|
| 토큰 없음 | 401 | 401 |
| 유출 시크릿 위조 | **200 (침입)** | **401 (차단)** |

실제 `jsonwebtoken` 라이브러리 + 실제 HTTP 서버 대상. 추정 아님.

---

## 5. 수정 (Remediation)

커밋 [`ae2d3fa`](https://github.com/ki0915/wiki-backend) — 브랜치 `security/fix-auth-vulns`

```diff
- const secretKey = 'my-secret-key';
+ const secretKey = process.env.JWT_SECRET;
+ if (!secretKey) {
+   throw new Error('JWT_SECRET environment variable is not set');
+ }
```
```diff
  const existUser = await User.findOne({
    where: {
      id: id,
-     password,          // 평문 password를 쿼리에서 제거 (bcrypt.compare가 인증)
    },
  });
```
```diff
- logger.info(`${id}에 ${token} 이 할당되었습니다.`);   // 토큰 로깅 제거 (CWE-532)
```
+ `.env.example`에 `JWT_SECRET` 문서화.

---

## 6. CI 통합 (DevSecOps 게이트)

정적 스캐너(`scan.py`)를 GitHub Action으로 통합. PR마다 자동 스캔.

```
$ python scan.py wiki-backend --mode static --fail-on high

[취약본]  4건 | high 2 medium 1 low 1 | 비용 0원 → CI 실패 (PR 차단)
[수정본]  1건 | medium 1            | 비용 0원 → CI 통과
```
- 무료 정적 티어 (LLM 0) — 매 커밋 부담 없음
- SARIF 출력 → GitHub Security 탭 연동
- high+ 발견 시 exit 1 → 취약 PR 자동 차단

---

## 7. Docker 재현 환경

격리 환경 재현용 `docker-compose` (MySQL + 앱) + `verify_e2e.sh` 준비.
```
docker compose -f docker/docker-compose.yml up --build -d
bash verify_e2e.sh    # 위조 토큰 HTTP 실증 (취약:200 / 수정:401)
```

---

## 8. 사용 기술 / 역량

- **취약점 분석:** JWT/인증 흐름 분석, CWE 분류, CIA 영향 판정
- **Exploit 실증:** 실제 라이브러리·HTTP 서버로 before/after 검증
- **수정:** 시크릿 관리(env), 인증 로직 교정, 민감정보 로깅 제거
- **DevSecOps:** 정적 스캐너 + SARIF + CI 게이트 + Docker 재현
- **정직성:** 실증 중 오탐(포트 잔존으로 인한 오판) 발견 시 즉시 정정

---

## 부록: 아티팩트

| 파일 | 내용 |
|------|------|
| `e2e_server.js` | authMiddleware 격리 실행 서버 |
| `poc_jwt_forge.js` | JWT 위조 PoC (라이브러리 검증) |
| `docker/docker-compose.yml` | MySQL + 앱 재현 환경 |
| `verify_e2e.sh` | e2e HTTP 위조 검증 스크립트 |
| `scripts/scan.py` | 다언어 정적 스캐너 (SARIF, CI 게이트) |
| 커밋 `ae2d3fa` | 4건 수정 |
