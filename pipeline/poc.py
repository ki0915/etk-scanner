"""
Stage 3b: PoC 실행 검증 (Docker 샌드박스).

전략 (2단계):
  1. 네트워크 허용 컨테이너에서 pip install → docker commit → 패키지 포함 이미지 생성
  2. --network none 컨테이너에서 PoC 실행 → 격리된 환경에서 검증

보안 제약:
  --network none      네트워크 완전 차단
  --memory 256m       메모리 제한
  --cpus 0.5          CPU 제한
  --read-only         루트 파일시스템 읽기 전용
  --cap-drop ALL      Linux 권한 전부 제거
  --no-new-privileges setuid/setcap 방지
  --user sandbox      비루트 사용자

Docker 없으면 subprocess 폴백 (경고 출력).
"""

from __future__ import annotations
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from .models import PoCResult

_SANDBOX_IMAGE = "ai-pentester-sandbox"
_SANDBOX_DIR   = Path(__file__).parent.parent / "docker" / "sandbox"


# ── Docker 가용 여부 ────────────────────────────────────────────────────────

def _docker_ok() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _ensure_image():
    """샌드박스 이미지가 없으면 빌드."""
    r = subprocess.run(
        ["docker", "image", "inspect", _SANDBOX_IMAGE],
        capture_output=True,
    )
    if r.returncode != 0:
        print(f"  [sandbox] 이미지 빌드 중: {_SANDBOX_IMAGE}")
        subprocess.run(
            ["docker", "build", "-t", _SANDBOX_IMAGE, str(_SANDBOX_DIR)],
            check=True,
        )


# ── Docker 기반 실행 ────────────────────────────────────────────────────────

def _run_docker(poc_code: str, package_name: str, timeout_secs: int) -> PoCResult:
    _ensure_image()

    run_id      = uuid.uuid4().hex[:8]
    install_ctr = f"sandbox_install_{run_id}"
    pkg_image   = f"sandbox_pkg_{run_id}"

    with tempfile.TemporaryDirectory() as tmpdir:
        poc_file = Path(tmpdir) / "poc.py"
        poc_file.write_text(poc_code, encoding="utf-8")

        try:
            # ── 1단계: 패키지 설치 (네트워크 허용) ────────────────────────
            install = subprocess.run(
                [
                    "docker", "run",
                    "--name", install_ctr,
                    "--memory", "512m",
                    "--cpus", "1",
                    _SANDBOX_IMAGE,
                    "pip", "install", package_name,
                    "-q", "--no-deps", "--disable-pip-version-check",
                ],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=120,
            )
            if install.returncode != 0:
                return PoCResult(
                    executed=False, vulnerable=False,
                    stdout="", stderr=install.stderr,
                    exit_code=install.returncode, evidence="",
                    error_msg=f"pip install 실패: {install.stderr[:300]}",
                )

            # ── 컨테이너 → 이미지 커밋 ────────────────────────────────────
            subprocess.run(
                ["docker", "commit", install_ctr, pkg_image],
                capture_output=True, check=True,
            )

            # ── 2단계: PoC 실행 (네트워크 차단, 격리) ─────────────────────
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", "none",          # 네트워크 완전 차단
                    "--memory", "256m",           # 메모리 제한
                    "--cpus", "0.5",              # CPU 제한
                    "--read-only",                # 루트 FS 읽기 전용
                    "--tmpfs", "/tmp:size=64m",   # /tmp만 쓰기 허용
                    "--cap-drop", "ALL",           # 권한 전부 제거
                    "--security-opt", "no-new-privileges",
                    "-v", f"{tmpdir}:/sandbox:ro",  # poc.py 읽기 전용 마운트
                    pkg_image,
                    "python", "/sandbox/poc.py",
                ],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout_secs + 5,
            )

        except subprocess.TimeoutExpired:
            return PoCResult(
                executed=False, vulnerable=False,
                stdout="", stderr="", exit_code=-1, evidence="",
                error_msg=f"타임아웃 ({timeout_secs}s)",
            )

        finally:
            # 컨테이너·이미지 정리
            subprocess.run(["docker", "rm", "-f", install_ctr], capture_output=True)
            subprocess.run(["docker", "rmi", "-f", pkg_image],  capture_output=True)

    stdout   = result.stdout or ""
    stderr   = result.stderr or ""
    evidence = ""
    vulnerable = False
    for line in stdout.splitlines():
        if "VULNERABLE:" in line:
            vulnerable = True
            evidence = line.split("VULNERABLE:", 1)[1].strip()
            break

    return PoCResult(
        executed=True, vulnerable=vulnerable,
        stdout=stdout[:2000], stderr=stderr[:1000],
        exit_code=result.returncode, evidence=evidence,
    )


# ── 로컬 subprocess 폴백 (Docker 없을 때) ───────────────────────────────────

def _run_local(poc_code: str, package_name: str, timeout_secs: int) -> PoCResult:
    with tempfile.TemporaryDirectory() as tmpdir:
        poc_file = Path(tmpdir) / "poc.py"
        poc_file.write_text(poc_code, encoding="utf-8")

        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name,
             "-q", "--no-deps", "--disable-pip-version-check"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=90,
        )
        if install.returncode != 0:
            return PoCResult(
                executed=False, vulnerable=False,
                stdout="", stderr=install.stderr,
                exit_code=install.returncode, evidence="",
                error_msg=f"설치 실패: {install.stderr[:200]}",
            )

        try:
            result = subprocess.run(
                [sys.executable, str(poc_file)],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout_secs, cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            return PoCResult(
                executed=False, vulnerable=False,
                stdout="", stderr="", exit_code=-1, evidence="",
                error_msg=f"타임아웃 ({timeout_secs}s)",
            )

        stdout = result.stdout or ""
        evidence = ""
        vulnerable = False
        for line in stdout.splitlines():
            if "VULNERABLE:" in line:
                vulnerable = True
                evidence = line.split("VULNERABLE:", 1)[1].strip()
                break

        return PoCResult(
            executed=True, vulnerable=vulnerable,
            stdout=stdout[:2000], stderr=(result.stderr or "")[:1000],
            exit_code=result.returncode, evidence=evidence,
        )


# ── 공개 인터페이스 ─────────────────────────────────────────────────────────

def run(poc_code: str, package_name: str, timeout_secs: int = 60) -> PoCResult:
    if _docker_ok():
        return _run_docker(poc_code, package_name, timeout_secs)
    else:
        print("  ⚠  Docker 없음 → 로컬 실행 (격리 없음)")
        return _run_local(poc_code, package_name, timeout_secs)
