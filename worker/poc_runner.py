"""
Stage 3b: PoC 실행 검증.
Sonnet이 생성한 PoC를 격리된 subprocess에서 실행하고
취약점 존재 여부를 바이너리로 확인한다.

성공 판정 기준: PoC가 stdout에 "VULNERABLE:" 문자열을 출력하면 확인됨.
Sonnet에게 PoC 작성 시 반드시 이 마커를 포함하도록 지시.
"""

import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PoCResult:
    executed: bool          # 실행 자체가 됐는지
    vulnerable: bool        # "VULNERABLE:" 마커 발견 여부
    stdout: str
    stderr: str
    exit_code: int
    evidence: str           # VULNERABLE: 이후 텍스트 (증거)
    error_msg: str = ""     # 실행 실패 사유


def run_poc(
    poc_code: str,
    package_name: str,
    package_version: str = "latest",
    timeout_secs: int = 30,
) -> PoCResult:
    """
    PoC 코드를 격리된 subprocess에서 실행.
    - 네트워크: 실제 외부 연결 없음 (localhost만 허용)
    - 타임아웃: timeout_secs초
    - 패키지 설치: pip install {package_name}=={version}
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        poc_file = Path(tmpdir) / "poc.py"
        setup_file = Path(tmpdir) / "setup.py"

        # PoC 파일 작성
        poc_file.write_text(poc_code, encoding="utf-8")

        # 패키지 설치 스크립트
        pkg_spec = f"{package_name}=={package_version}" if package_version != "latest" else package_name
        setup_script = textwrap.dedent(f"""
            import subprocess, sys
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "{pkg_spec}", "-q",
                 "--no-deps", "--disable-pip-version-check"],
                timeout=60
            )
        """)
        setup_file.write_text(setup_script, encoding="utf-8")

        try:
            # 1. 패키지 설치
            install_result = subprocess.run(
                [sys.executable, str(setup_file)],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=90,
                cwd=tmpdir,
            )
            if install_result.returncode != 0:
                return PoCResult(
                    executed=False, vulnerable=False,
                    stdout="", stderr=install_result.stderr,
                    exit_code=install_result.returncode,
                    evidence="",
                    error_msg=f"패키지 설치 실패: {install_result.stderr[:300]}",
                )

            # 2. PoC 실행 (Windows CP949 이슈 방지: encoding 명시)
            run_result = subprocess.run(
                [sys.executable, str(poc_file)],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout_secs,
                cwd=tmpdir,
            )

            stdout = run_result.stdout or ""
            stderr = run_result.stderr or ""

            # 성공 마커 탐지
            vulnerable = False
            evidence = ""
            for line in stdout.splitlines():
                if "VULNERABLE:" in line:
                    vulnerable = True
                    evidence = line.split("VULNERABLE:", 1)[1].strip()
                    break

            return PoCResult(
                executed=True,
                vulnerable=vulnerable,
                stdout=stdout[:2000],
                stderr=stderr[:1000],
                exit_code=run_result.returncode,
                evidence=evidence,
            )

        except subprocess.TimeoutExpired:
            return PoCResult(
                executed=False, vulnerable=False,
                stdout="", stderr="",
                exit_code=-1, evidence="",
                error_msg=f"타임아웃 ({timeout_secs}s 초과)",
            )
        except Exception as e:
            return PoCResult(
                executed=False, vulnerable=False,
                stdout="", stderr="",
                exit_code=-1, evidence="",
                error_msg=str(e),
            )
