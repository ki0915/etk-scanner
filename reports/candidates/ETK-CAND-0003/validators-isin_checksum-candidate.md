# [후보] validators: _isin_checksum — CWE-682 (Incorrect Calculation)

| 항목 | 내용 |
|------|------|
| 작성 시각 | 2026-05-31 23:02 |
| 패키지 | validators |
| 대상 함수 | `_isin_checksum` |
| 심각도 (추정) | unknown |
| CWE | CWE-682 (Incorrect Calculation) |
| 재현 상태 | ⚠️ 재현 실패 (리포트 보류 권장) |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) |

---

## 보안 의도 (Security Intent)

Validate that a 12-character ISIN string has a correct Luhn-based check digit, rejecting ISINs with invalid/forged check digits

## 취약점 요약

The variable `check` is initialized to 0 and is never accumulated inside the loop (the line `check = check + (val // 10) + (val % 10)` present in the sibling _cusip_checksum is missing). As a result, the final expression `(check % 10) == 0` always evaluates to `(0 % 10) == 0 → True`, making the checksum validation completely inoperative. Any 12-character string of valid ISIN characters passes regardless of whether the check digit is mathematically correct.

## 보안 경계 위반

Validate that a 12-character ISIN string has a correct Luhn-based check digit, rejecting ISINs with invalid/forged check digits

## 현실적 악용 시나리오

Any 12-character string with valid ISIN characters but wrong check digit, e.g. 'US0378331000' (Apple ISIN with last digit 0 instead of correct 5), or 'AAAAAAAAAAAA' — all return True instead of the correct False

## 공격 벡터

Any 12-character string with valid ISIN characters but wrong check digit, e.g. 'US0378331000' (Apple ISIN with last digit 0 instead of correct 5), or 'AAAAAAAAAAAA' — all return True instead of the correct False

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

**반론:** The variable `check` is initialized to 0 and is never accumulated inside the loop (the line `check = check + (val // 10) + (val % 10)` present in the sibling _cusip_checksum is missing). As a result, the final expression `(check % 10) == 0` always evaluates to `(0 % 10) == 0 → True`, making the checksum validation completely inoperative. Any 12-character string of valid ISIN characters passes regardless of whether the check digit is mathematically correct.

---

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색
- [ ] 최신 버전에서도 재현되는지 확인 (이 리포트는 클론된 버전 기준)
- [ ] 위 '악용 시나리오'가 실제 사용 패턴인지 재확인
- [ ] 메인테이너 반박이 반론으로 막히는지 최종 판단
- [ ] CVSS 점수는 메인테이너 판단에 맡기는 톤으로 작성

## 참고

- 대상 소스: `candidates\ETK-CAND-0003-validators\repo`
- 자동 판정 신뢰도: 1.0
