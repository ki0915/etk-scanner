# validators: `private=False` IP filter does not classify IPv6 internal addresses — SSRF allowlist bypass

| 항목 | 내용 |
|------|------|
| 작성 시각 | 2026-05-31 |
| 패키지 | validators (PyPI) |
| 주간 다운로드 | 약 7,230,000 |
| 대상 함수 | `ipv6()` / `_check_private_ip()` (`src/validators/ip_address.py`), `url(..., private=False)` |
| 취약점 타입 | SSRF allowlist bypass / Incomplete IP classification |
| CWE | CWE-918 (SSRF), CWE-697 (Incorrect Comparison) |
| CVSS 3.1 (추정) | 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N *(심각도는 메인테이너 판단에 위임)* |
| 재현 상태 | ✅ 실제 라이브러리로 재현 확인 |
| 발견 방식 | 자동 파이프라인 (intent_finder → agent → exploit_gate) + 수동 검증 |
| **신고 여부** | **❌ 신고 안 함 (DO NOT REPORT)** — 아래 사유 참조 |

> ## ⛔ 신고 보류 결정 (2026-05-31)
>
> 신고 전 중복 확인에서 두 가지가 드러나 **validators CVE로는 부적합**으로 판단:
>
> 1. **이미 공개 알려짐**: open-webui 보안 advisory **GHSA-4v7r-f4w8-8972** (2026-05-09)가
>    validators의 IPv6 `private` 미구현 + IPv4-mapped IPv6(`::ffff:...`) 우회를 이미 서술.
>    우리가 처음 발견한 것이 아님.
> 2. **책임 소재가 validators가 아님**: 생태계는 "validators는 IPv6 `private`을 지원하지
>    않으며(호출 시 ValidationError 신호), SSRF 방어로 사용한 애플리케이션 측 책임"으로 정리.
>    open-webui가 **자사 CVE**로 수용 (validators CVE 아님). validators는 "private은 IPv4
>    전용 의도"로 닫을 명분 충분.
>
> **결론**: 파이프라인의 탐지 자체는 성공(진짜 위험 지점을 짚음 — open-webui CVE가 증거).
> 그러나 책임 소재가 라이브러리에 없고 기지 사실이므로 validators 대상 신고는 하지 않음.
> 이 문서는 파이프라인 검증 기록으로만 보존.

---

## 요약

`validators`의 `ipv4()`/`ipv6()`/`url()`/`hostname()`은 `private` 인자를 받습니다.
문서상 `private=False`는 **"임베드된 IP 주소가 public이어야 한다"**는 의미로,
SSRF 방어용 allowlist(내부 주소 차단)로 사용될 수 있습니다.

그러나 private/public 분류 로직 `_check_private_ip()`는 **IPv4 문자열 prefix
매칭만** 수행하며 **IPv6를 전혀 분류하지 않습니다.** 그 결과:

- IPv4 루프백/메타데이터(`127.0.0.1`, `169.254.169.254`)는 올바르게 **차단**되지만
- 동등한 IPv6 표현(`::1`, `[::ffff:169.254.169.254]`, `fc00::/7`, `fe80::/10`)은
  모두 **"public"으로 통과**됩니다.

특히 **IPv4-mapped IPv6** (`::ffff:169.254.169.254`)는 IPv4 경로가 차단하는
바로 그 클라우드 메타데이터 엔드포인트에 도달합니다. IPv4는 막고 IPv6 표기로는
통과되는 **불일치(asymmetry)** 가 이 동작이 의도된 것이 아님을 보여줍니다.

---

## 취약 코드

**`src/validators/ip_address.py`**

```python
def _check_private_ip(value: str, is_private: Optional[bool]):
    if is_private is None:
        return True
    if (
        any(
            value.startswith(l_bit)
            for l_bit in {
                "10.", "192.168.", "169.254.", "127.", "0.0.0.0",
            }
        )
        or re.match(r"^172\.(?:1[6-9]|2\d|3[0-1])\.", value)   # IPv4 전용
        or re.match(r"^(?:22[4-9]|23[0-9]|24[0-9]|25[0-5])\.", value)
    ):
        return is_private
    return not is_private
```

```python
@validator
def ipv6(value: str, /, *, cidr=True, strict=False, host_bit=True):
    # private 인자도 없고, _check_private_ip 호출도 없음
    # → ipv6는 private/public 분류를 전혀 하지 않는다
    ...
```

`_check_private_ip`는 IPv4 점-십진 표기 prefix만 검사합니다. IPv6 리터럴은
어떤 분기에도 걸리지 않아 항상 마지막 `return not is_private`로 떨어집니다.
즉 `private=False`일 때 모든 IPv6는 `not False = True`(=public, 통과)가 됩니다.

`url(..., private=False)`는 netloc의 호스트가 IP일 때 이 분류에 의존하므로
동일하게 우회됩니다.

---

## PoC (실제 실행 출력)

```python
import validators as v

# private=False = "공개 IP만 허용" (SSRF 방어 의도)
tests = [
    'http://[::1]/admin',                 # IPv6 loopback
    'http://[::ffff:127.0.0.1]/',         # IPv4-mapped loopback
    'http://[::ffff:169.254.169.254]/',   # IPv4-mapped cloud metadata
    'http://[fc00::1]/',                  # IPv6 unique-local (내부망)
    'http://[fe80::1]/',                  # IPv6 link-local
    'http://127.0.0.1/',                  # IPv4 loopback (대조군)
    'http://169.254.169.254/',            # IPv4 metadata (대조군)
]
for u in tests:
    allowed = v.url(u, private=False) is True
    print('ALLOWED' if allowed else 'blocked', u)
```

**실행 결과 (validators, Python 3.13):**
```
ALLOWED http://[::1]/admin
ALLOWED http://[::ffff:127.0.0.1]/
ALLOWED http://[::ffff:169.254.169.254]/
ALLOWED http://[fc00::1]/
ALLOWED http://[fe80::1]/
blocked http://127.0.0.1/
blocked http://169.254.169.254/
```

IPv4 내부 주소는 차단되는데 동등한 IPv6/IPv4-mapped 표현은 전부 "public"으로
통과합니다.

---

## 표준 라이브러리 대조 (정답지)

```python
import ipaddress
ipaddress.ip_address('::1').is_loopback              # True  (validators: public)
ipaddress.ip_address('::ffff:169.254.169.254').is_private  # 내부 주소
ipaddress.ip_address('fc00::1').is_private           # True  (validators: public)
ipaddress.ip_address('fe80::1').is_link_local        # True  (validators: public)
```

Python 표준 `ipaddress`는 이들을 모두 내부/특수 주소로 정확히 분류합니다.
validators는 stdlib를 쓰지 않고 손으로 짠 IPv4 전용 prefix 매칭을 사용해
IPv6 전체를 누락했습니다.

---

## 영향 / 악용 시나리오

웹 애플리케이션이 사용자 제공 URL(웹훅, 이미지 fetch, 리다이렉트 대상)을
`validators.url(user_url, private=False)`로 검증해 내부 대상을 차단하는
SSRF allowlist로 사용하는 경우:

- 공격자가 `http://[::ffff:169.254.169.254]/latest/meta-data/`를 제출
- IPv4 `169.254.169.254`였다면 차단됐겠지만 IPv4-mapped IPv6 표기는 통과
- 서버가 이 URL로 요청 → 클라우드 메타데이터(자격증명) 노출 가능
- 또는 `http://[::1]:<port>/`로 내부 서비스 접근

---

## Devil's Advocate

**예상 반박:** "`private`은 IPv4 전용으로 설계됐다(`_check_private_ip`는 ipv4
경로에서만 의도됨). url()을 SSRF 통제로 쓰지 말라. IPv6 미구현은 범위 밖이지
취약점이 아니다."

**반론:**
1. `ipv6()`와 `url()`은 IPv6 리터럴을 정상 입력으로 받으며, `private=False`에
   대해 **조용히 True(public)** 를 반환한다 — 명시적 에러나 미지원 신호 없이.
   IPv6도 명백히 IP 주소이며, 문서는 `private=False`를 무조건 "public"으로 기술한다.
2. IPv4는 정확히 차단하면서 동등한 IPv6/IPv4-mapped 표현은 통과시키는 것은
   **일관성 없는 보안 결과(inconsistent, deceptive)** 이지 단순 미구현이 아니다.
3. `::ffff:169.254.169.254`는 IPv4 경로가 막는 **동일한 IPv4 타겟**에 연결된다.
   "공개 전용" 플래그가 루프백/메타데이터를 허용하는 것은 CWE-918 SSRF
   allowlist 우회의 정의에 부합한다.

---

## 완화 방안

`_check_private_ip`를 손으로 짠 prefix 매칭 대신 표준 `ipaddress`로 교체하고
IPv6를 포함:

```python
import ipaddress

def _check_private_ip(value: str, is_private: Optional[bool]):
    if is_private is None:
        return True
    try:
        ip = ipaddress.ip_address(value.split("/")[0])
    except ValueError:
        return not is_private
    # IPv4-mapped IPv6는 내장 IPv4로 환원해 함께 판정
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    actually_private = (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast
    )
    return is_private if actually_private else not is_private
```

그리고 `ipv6()`에도 `ipv4()`와 동일하게 `private` 인자 및 분류를 적용.

---

## 신고 전 수동 확인 체크리스트

- [ ] CVE/GHSA/GitHub 이슈에 동일 건이 이미 보고됐는지 검색 (validators SSRF / private IPv6)
- [ ] 최신 PyPI 버전에서도 재현되는지 확인 (이 리포트는 main 클론 기준)
- [ ] `private` 인자의 공식 문서 문구를 인용해 "보안 경계" 주장 보강
- [ ] CVSS는 메인테이너 판단에 위임하는 톤 유지

## 참고

- 취약 파일: `src/validators/ip_address.py` (`_check_private_ip`, `ipv6`)
- CWE-918: Server-Side Request Forgery
- CWE-697: Incorrect Comparison
- 표준 대조: Python `ipaddress` 모듈 (`is_private`, `is_loopback`, `ipv4_mapped`)
- 발견 경로: 자동 파이프라인이 `_check_private_ip`를 보안 의도 함수로 식별 →
  에이전트가 stdlib 대조 + IPv6 PoC로 우회 확인 → 악용성 게이트 통과
