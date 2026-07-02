# [후보] validators: _validate_netloc — CWE-918

| 항목 | 내용 |
|------|------|
| 작성 시각 | 2026-05-31 21:46 |
| 패키지 | validators |
| 대상 함수 | `_validate_netloc` |
| 심각도 (추정) | medium |
| CWE | CWE-918 |
| 재현 상태 | ⚠️ 재현 실패 (리포트 보류 권장) |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) |

---

## 보안 의도 (Security Intent)

The `private=False` filter on url()/hostname() is meant to require publicly-routable IP destinations only, rejecting private/loopback/link-local addresses. The boundary is completely absent for IPv6: ipv6() is invoked with no private filtering, so loopback (::1), IPv4-mapped loopback/metadata ([::ffff:127.0.0.1], [::ffff:169.254.169.254]), unique-local (fc00::/7) and link-local (fe80::/10) IPv6 literals pass as 'public'.

## 취약점 요약

agent could not finalize verdict; escalating

## 보안 경계 위반

The `private=False` filter on url()/hostname() is meant to require publicly-routable IP destinations only, rejecting private/loopback/link-local addresses. The boundary is completely absent for IPv6: ipv6() is invoked with no private filtering, so loopback (::1), IPv4-mapped loopback/metadata ([::ffff:127.0.0.1], [::ffff:169.254.169.254]), unique-local (fc00::/7) and link-local (fe80::/10) IPv6 literals pass as 'public'.

## 현실적 악용 시나리오

An application validates a user-supplied webhook/fetch/redirect URL with validators.url(u, private=False) as an SSRF allowlist to block internal targets. IPv4 loopback/metadata are correctly rejected, but the attacker supplies http://[::ffff:169.254.169.254]/ or http://[::1]/admin to reach cloud metadata / loopback services, since those return True.

## 공격 벡터

?

---

## 검증된 PoC (실제 실행 출력)

아래 PoC는 리포트 생성 시점에 **실제로 실행되어** 출력이 박제되었습니다.

```python
import validators as v
def is_safe(u):
    return v.url(u, private=False) is True
for a in ['http://[::1]/admin','http://[::ffff:127.0.0.1]/admin','http://[::ffff:169.254.169.254]/','http://[fc00::1]/','http://[fe80::1]/','http://127.0.0.1/','http://169.254.169.254/']:
    print('ALLOWED' if is_safe(a) else 'blocked', a)
```

**실행 출력:**
```
EXIT=0
ALLOWED http://[::1]/admin
ALLOWED http://[::ffff:127.0.0.1]/admin
ALLOWED http://[::ffff:169.254.169.254]/
ALLOWED http://[fc00::1]/
ALLOWED http://[fe80::1]/
blocked http://127.0.0.1/
blocked http://169.254.169.254/
```

---

## Devil's Advocate (메인테이너 반박 대비)

**예상 반박:** The inline comment says `private` is `# only for ip-addresses` and the implementation (_check_private_ip) was only ever designed for IPv4; users should not rely on url() as an SSRF control, and the IPv6 behavior is just unimplemented scope, not a vulnerability.

**반론:** IPv6 literals ARE ip-addresses, and the public docstring states unconditionally that private=False means the embedded IP address is public. The function silently returns True for loopback/link-local/private IPv6 while correctly rejecting their IPv4 equivalents, which is an inconsistent and deceptive security result, not merely an unimplemented option. A documented public-only flag that admits loopback is precisely the SSRF-allowlist bypass pattern that defines CWE-918, and the IPv4-mapped forms (::ffff:127.0.0.1) connect to the same IPv4 targets the IPv4 path blocks.

---

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색
- [ ] 최신 버전에서도 재현되는지 확인 (이 리포트는 클론된 버전 기준)
- [ ] 위 '악용 시나리오'가 실제 사용 패턴인지 재확인
- [ ] 메인테이너 반박이 반론으로 막히는지 최종 판단
- [ ] CVSS 점수는 메인테이너 판단에 맡기는 톤으로 작성

## 참고

- 대상 소스: `candidates\ETK-CAND-0003-validators\repo`
- 자동 판정 신뢰도: 0.7
