# [후보] validators: _check_private_ip — CWE-184: Incomplete List of Disallowed Inputs

| 항목 | 내용 |
|------|------|
| 작성 시각 | 2026-05-31 23:13 |
| 패키지 | validators |
| 대상 함수 | `_check_private_ip` |
| 심각도 (추정) | medium |
| CWE | CWE-184: Incomplete List of Disallowed Inputs |
| 재현 상태 | ⚠️ 재현 실패 (리포트 보류 권장) |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) |

---

## 보안 의도 (Security Intent)

Classify IPv4 addresses as private/reserved vs public — validators.ipv4(ip, private=False) should reject all private/reserved IPs and only accept genuinely public ones

## 취약점 요약

The hand-rolled checker only covers a subset of RFC-defined private/reserved ranges (RFC 1918, link-local, localhost, multicast). It misses 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, and 203.0.113.0/24 — all classified as is_private=True by Python's stdlib ipaddress module. An attacker can pass IPs from these ranges through a private=False filter.

## 보안 경계 위반

Public vs. private/reserved IP classification boundary — used to prevent SSRF or restrict network access to internal resources

## 현실적 악용 시나리오

198.18.0.1, 198.51.100.1, 203.0.113.1, 0.1.2.3, 192.0.0.1, or 192.0.2.1 — all pass validators.ipv4(ip, private=False) but are correctly identified as private/reserved by Python's ipaddress.IPv4Address(ip).is_private

## 공격 벡터

198.18.0.1, 198.51.100.1, 203.0.113.1, 0.1.2.3, 192.0.0.1, or 192.0.2.1 — all pass validators.ipv4(ip, private=False) but are correctly identified as private/reserved by Python's ipaddress.IPv4Address(ip).is_private

---

## 검증된 PoC (실제 실행 출력)

아래 PoC는 리포트 생성 시점에 **실제로 실행되어** 출력이 박제되었습니다.

```python

```

**실행 출력:**
```
(no PoC code)
```

---

## Devil's Advocate (메인테이너 반박 대비)

**예상 반박:** 

**반론:** The hand-rolled checker only covers a subset of RFC-defined private/reserved ranges (RFC 1918, link-local, localhost, multicast). It misses 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, and 203.0.113.0/24 — all classified as is_private=True by Python's stdlib ipaddress module. An attacker can pass IPs from these ranges through a private=False filter.

---

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색
- [ ] 최신 버전에서도 재현되는지 확인 (이 리포트는 클론된 버전 기준)
- [ ] 위 '악용 시나리오'가 실제 사용 패턴인지 재확인
- [ ] 메인테이너 반박이 반론으로 막히는지 최종 판단
- [ ] CVSS 점수는 메인테이너 판단에 맡기는 톤으로 작성

## 참고

- 대상 소스: `candidates\ETK-CAND-0003-validators\repo`
- 자동 판정 신뢰도: 0.62
