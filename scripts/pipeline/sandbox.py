"""
sandbox.py — LLM이 작성한 PoC를 격리 컨테이너에서만 실행

원칙:
  1. 호스트에서 직접 실행하지 않는다. Docker를 쓸 수 없으면 실행을 거부한다.
  2. 호스트 환경변수를 넘기지 않는다. (API 키 등 비밀값 차단)
     컨테이너에는 아래 _ALLOWED_ENV 값만 명시적으로 주입한다.
  3. 네트워크 없음, 루트 파일시스템 읽기 전용, 권한(capability) 전부 제거,
     비루트 사용자, 프로세스·메모리·CPU 상한.
  4. 분석 대상 코드는 읽기 전용으로 마운트한다.

이미지: docker/sandbox/Dockerfile (기본 태그 etk-sandbox:latest)
  docker build -t etk-sandbox:latest docker/sandbox
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IMAGE = "etk-sandbox:latest"

# 컨테이너 안으로 넘기는 환경변수 — 이 목록 밖의 값은 절대 넘기지 않는다
_ALLOWED_ENV = ("PYTHONPATH", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE")

# docker CLI 프로세스 자체에 넘길 최소 환경 (CLI도 비밀값을 들고 있을 이유가 없음)
_DOCKER_CLI_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT")


@dataclass
class SandboxConfig:
    image: str = DEFAULT_IMAGE
    timeout: int = 10
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 64
    user: str = "1000:1000"


@dataclass
class SandboxResult:
    exit_code: int | None
    output: str
    timed_out: bool = False
    blocked: str = ""          # 실행 자체를 거부한 이유 (빈 문자열이면 실행됨)
    command: list[str] = field(default_factory=list)

    def to_tool_text(self) -> str:
        if self.blocked:
            return f"{self.blocked}: PoC was NOT executed."
        if self.timed_out:
            return "TIMEOUT"
        return f"EXIT={self.exit_code}\n{self.output}"


def docker_available() -> bool:
    """docker CLI가 있고 데몬에 접속되는가."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10,
                           env=_docker_cli_env())
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _docker_cli_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _DOCKER_CLI_ENV if k in os.environ}


def build_command(code_dir: Path, repo_path: Path, name: str,
                  cfg: SandboxConfig) -> list[str]:
    """격리 옵션이 모두 들어간 docker run 명령을 만든다 (실행하지 않음)."""
    repo = repo_path.resolve()
    pythonpath = "/target/src:/target" if (repo / "src").is_dir() else "/target"
    env = {
        "PYTHONPATH": pythonpath,
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(cfg.pids_limit),
        "--memory", cfg.memory,
        "--cpus", cfg.cpus,
        "--user", cfg.user,
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{code_dir.resolve()}:/sandbox:ro",
        "-v", f"{repo}:/target:ro",
        "-w", "/sandbox",
    ]
    for k in _ALLOWED_ENV:
        cmd += ["-e", f"{k}={env[k]}"]
    cmd += [cfg.image, "python", "/sandbox/poc.py"]
    return cmd


def run_python(code: str, repo_path: str | Path,
               cfg: SandboxConfig | None = None) -> SandboxResult:
    """PoC 코드를 컨테이너에서 실행. Docker가 없으면 실행하지 않고 거부한다."""
    cfg = cfg or SandboxConfig()
    if not docker_available():
        return SandboxResult(None, "", blocked="SANDBOX_UNAVAILABLE")

    name = f"etk-poc-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as tmp:
        code_dir = Path(tmp)
        (code_dir / "poc.py").write_text(code, encoding="utf-8")
        os.chmod(code_dir, 0o755)
        os.chmod(code_dir / "poc.py", 0o644)
        cmd = build_command(code_dir, Path(repo_path), name, cfg)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=cfg.timeout, env=_docker_cli_env(),
                               encoding="utf-8", errors="replace")
            return SandboxResult(r.returncode, (r.stdout + r.stderr)[:3000],
                                 command=cmd)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True,
                           timeout=10, env=_docker_cli_env())
            return SandboxResult(None, "", timed_out=True, command=cmd)
