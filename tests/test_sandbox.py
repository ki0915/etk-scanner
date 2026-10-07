"""샌드박스 격리 테스트.

단위 테스트: Docker 데몬 없이 명령 구성과 비밀값 차단을 검증한다.
통합 테스트: Docker가 있을 때만 실제 컨테이너에서 격리를 확인한다.
"""

import subprocess
from pathlib import Path

import pytest

from pipeline import sandbox
from pipeline.agent_tools import ToolBox

SECRET = "sk-ant-test-SHOULD-NEVER-LEAK"


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET)


def _cmd(tmp_path):
    return sandbox.build_command(tmp_path, tmp_path, "etk-poc-test",
                                 sandbox.SandboxConfig())


# ── 명령 구성 ────────────────────────────────────────────────────────────────

def test_isolation_flags_present(tmp_path):
    cmd = " ".join(_cmd(tmp_path))
    for flag in ("--network none", "--read-only", "--cap-drop ALL",
                 "--security-opt no-new-privileges", "--user 1000:1000",
                 "--pids-limit", "--memory"):
        assert flag in cmd, f"격리 옵션 누락: {flag}"


def test_mounts_are_read_only(tmp_path):
    cmd = _cmd(tmp_path)
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts and all(m.endswith(":ro") for m in mounts)


def test_only_allowlisted_env_in_container(tmp_path, secret_env):
    cmd = _cmd(tmp_path)
    passed = [cmd[i + 1].split("=")[0] for i, a in enumerate(cmd) if a == "-e"]
    assert set(passed) <= set(sandbox._ALLOWED_ENV)
    assert SECRET not in " ".join(cmd)


# ── 실행 경로 ────────────────────────────────────────────────────────────────

def test_refuses_without_docker_and_never_runs_on_host(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    r = sandbox.run_python("print('hi')", tmp_path)
    assert r.blocked == "SANDBOX_UNAVAILABLE"
    assert calls == [], "Docker가 없을 때 아무것도 실행하면 안 된다"


def test_docker_cli_process_gets_no_secrets(tmp_path, monkeypatch, secret_env):
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", fake_run)
    r = sandbox.run_python("print('ok')", tmp_path)
    assert r.exit_code == 0 and r.command[:2] == ["docker", "run"]
    assert seen["env"] is not None, "env=None 이면 호스트 환경 전체가 상속된다"
    assert SECRET not in seen["env"].values()


def test_timeout_kills_container(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", fake_run)
    r = sandbox.run_python("while True: pass", tmp_path)
    assert r.timed_out
    name = calls[0][calls[0].index("--name") + 1]
    assert ["docker", "kill", name] in calls


def test_toolbox_run_poc_goes_through_sandbox(tmp_path, monkeypatch):
    got = {}

    def fake(code, repo, cfg=None):
        got["code"] = code
        return sandbox.SandboxResult(0, "fine")

    monkeypatch.setattr(sandbox, "run_python", fake)
    tb = ToolBox(tmp_path / "graph.db", tmp_path)
    assert tb.run_poc("print(1)") == "EXIT=0\nfine"
    assert got["code"] == "print(1)"


def test_toolbox_reports_unavailable_sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    tb = ToolBox(tmp_path / "graph.db", tmp_path)
    assert tb.run_poc("print(1)").startswith("SANDBOX_UNAVAILABLE")


# ── 통합 (실제 Docker 필요) ──────────────────────────────────────────────────

def _image_ready() -> bool:
    if not sandbox.docker_available():
        return False
    r = subprocess.run(["docker", "image", "inspect", sandbox.DEFAULT_IMAGE],
                       capture_output=True)
    return r.returncode == 0


needs_docker = pytest.mark.skipif(
    not _image_ready(),
    reason="Docker 데몬 + etk-sandbox 이미지 필요: docker build -t etk-sandbox:latest docker/sandbox",
)


@needs_docker
def test_real_container_has_no_secret(tmp_path, secret_env):
    r = sandbox.run_python(
        "import os; print('LEAK' if any('sk-ant' in v for v in os.environ.values()) else 'CLEAN')",
        tmp_path)
    assert r.exit_code == 0 and "CLEAN" in r.output


@needs_docker
def test_real_container_has_no_network(tmp_path):
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3); print('ONLINE')\n"
        "except OSError:\n"
        "    print('OFFLINE')\n"
    )
    r = sandbox.run_python(code, tmp_path)
    assert "OFFLINE" in r.output


@needs_docker
def test_real_container_target_is_read_only(tmp_path):
    r = sandbox.run_python(
        "open('/target/pwned.txt', 'w').write('x')", tmp_path)
    assert r.exit_code != 0
    assert not (tmp_path / "pwned.txt").exists()
