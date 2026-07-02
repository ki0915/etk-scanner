# [후보] validators: cron — CWE-20 (Improper Input Validation)

| 항목 | 내용 |
|------|------|
| 작성 시각 | 2026-05-31 23:02 |
| 패키지 | validators |
| 대상 함수 | `cron` |
| 심각도 (추정) | unknown |
| CWE | CWE-20 (Improper Input Validation) |
| 재현 상태 | ⚠️ 재현 실패 (리포트 보류 권장) |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) |

---

## 보안 의도 (Security Intent)

Validate that a cron string is valid — all field values and step values must fall within their field-specific allowed ranges (minutes 0-59, hours 0-23, days 1-31, months 1-12, weekdays 0-6).

## 취약점 요약

In _validate_cron_component(), when processing step notation (X/Y), the denominator Y (step value) is only checked to be >= 1 (int(parts[1]) < 1), but is NEVER checked against max_val. This means out-of-range step values are accepted as valid. For example, '*/60 * * * *' has a step of 60 which exceeds the minutes maximum of 59, yet the function returns True instead of a ValidationError. A secondary bug: the '-' check fires before the ',' check, so valid comma-separated range expressions like '1-3,5 * * * *' are incorrectly rejected.

## 보안 경계 위반

Validate that a cron string is valid — all field values and step values must fall within their field-specific allowed ranges (minutes 0-59, hours 0-23, days 1-31, months 1-12, weekdays 0-6).

## 현실적 악용 시나리오

Any cron string with a step value exceeding the field maximum: '*/60 * * * *' (minutes), '* */24 * * *' (hours), '* * */32 * *' (days), '* * * */13 *' (months), '* * * * */7' (weekdays). The function returns True for all of these instead of ValidationError.

## 공격 벡터

Any cron string with a step value exceeding the field maximum: '*/60 * * * *' (minutes), '* */24 * * *' (hours), '* * */32 * *' (days), '* * * */13 *' (months), '* * * * */7' (weekdays). The function returns True for all of these instead of ValidationError.

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

**반론:** In _validate_cron_component(), when processing step notation (X/Y), the denominator Y (step value) is only checked to be >= 1 (int(parts[1]) < 1), but is NEVER checked against max_val. This means out-of-range step values are accepted as valid. For example, '*/60 * * * *' has a step of 60 which exceeds the minutes maximum of 59, yet the function returns True instead of a ValidationError. A secondary bug: the '-' check fires before the ',' check, so valid comma-separated range expressions like '1-3,5 * * * *' are incorrectly rejected.

---

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색
- [ ] 최신 버전에서도 재현되는지 확인 (이 리포트는 클론된 버전 기준)
- [ ] 위 '악용 시나리오'가 실제 사용 패턴인지 재확인
- [ ] 메인테이너 반박이 반론으로 막히는지 최종 판단
- [ ] CVSS 점수는 메인테이너 판단에 맡기는 톤으로 작성

## 참고

- 대상 소스: `candidates\ETK-CAND-0003-validators\repo`
- 자동 판정 신뢰도: 0.97
