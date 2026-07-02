# Submission text — validators IPv6 SSRF
# Post to: https://github.com/python-validators/validators/discussions/categories/security
# (SECURITY.md directs security reports to the "security" Discussions category)

---

## Title

`private=False` filter does not classify IPv6 addresses — internal IPv6 targets pass as "public"

---

## Body

Hi, and thanks for maintaining `validators`.

I noticed a possible gap in how the `private` flag handles IPv6, and wanted to flag it
in case it's unintended. Apologies if this is already known or considered out of scope.

### What I observed

`ipv4()`, `ipv6()`, `url()` and `hostname()` accept a `private` argument. The docs
describe `private=False` as meaning the address must be public, which makes it a natural
choice for an SSRF allowlist (reject internal targets).

For IPv4 this works — loopback and link-local are correctly rejected. But the same
internal addresses expressed as IPv6 (or IPv4-mapped IPv6) appear to pass as "public":

```python
import validators as v

for u in [
    'http://[::1]/admin',                 # IPv6 loopback
    'http://[::ffff:127.0.0.1]/',         # IPv4-mapped loopback
    'http://[::ffff:169.254.169.254]/',   # IPv4-mapped cloud metadata
    'http://[fc00::1]/',                  # IPv6 unique-local
    'http://[fe80::1]/',                  # IPv6 link-local
    'http://127.0.0.1/',                  # IPv4 loopback (control)
    'http://169.254.169.254/',            # IPv4 metadata (control)
]:
    print('ALLOWED' if v.url(u, private=False) is True else 'blocked', u)
```

Output (validators latest, Python 3.13):

```
ALLOWED http://[::1]/admin
ALLOWED http://[::ffff:127.0.0.1]/
ALLOWED http://[::ffff:169.254.169.254]/
ALLOWED http://[fc00::1]/
ALLOWED http://[fe80::1]/
blocked http://127.0.0.1/
blocked http://169.254.169.254/
```

The IPv4 internal addresses are blocked, but the equivalent IPv6 / IPv4-mapped forms
are allowed. Notably `[::ffff:169.254.169.254]` reaches the exact same metadata endpoint
that the IPv4 path blocks.

### Where it comes from

In `src/validators/ip_address.py`, `_check_private_ip()` only matches IPv4 dotted-decimal
prefixes/regex (`10.`, `192.168.`, `169.254.`, `127.`, `172.16–31`, multicast). IPv6
literals match none of these branches, so they fall through to `return not is_private`
(i.e. treated as public when `private=False`).

Also, `ipv6()` has no `private` parameter, and `hostname()` calls `ipv6(host_seg,
cidr=False)` without passing the flag — so the private filter is effectively skipped for
IPv6 hosts in URLs.

For comparison, Python's stdlib classifies all of these as internal:

```python
import ipaddress
ipaddress.ip_address('::1').is_loopback              # True
ipaddress.ip_address('fc00::1').is_private           # True
ipaddress.ip_address('fe80::1').is_link_local        # True
ipaddress.ip_address('::ffff:169.254.169.254').ipv4_mapped  # 169.254.169.254
```

### Why I think it may be worth addressing

If an application uses `validators.url(user_url, private=False)` (or `hostname(...)`) as
an SSRF guard, an attacker could supply `http://[::ffff:169.254.169.254]/latest/meta-data/`
or `http://[::1]:<port>/` to reach internal services that the IPv4 path would block. The
inconsistency between IPv4 and IPv6 is what made me think this is unintended rather than a
deliberate "IPv6 not supported" choice — there's no error or signal, it just silently
returns public.

### Possible direction (only a suggestion)

Routing the classification through stdlib `ipaddress` would cover both families and
IPv4-mapped forms, e.g.:

```python
import ipaddress

def _check_private_ip(value, is_private):
    if is_private is None:
        return True
    try:
        ip = ipaddress.ip_address(value.split('/')[0])
    except ValueError:
        return not is_private
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    internal = (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast)
    return is_private if internal else not is_private
```

…and giving `ipv6()` the same `private` parameter that `ipv4()` has.

If this is actually intended behavior or `private` isn't meant as a security boundary,
I'd appreciate the clarification and will update my understanding. Happy to provide more
detail or open a PR if that's helpful.

Thanks again for your work on this.
