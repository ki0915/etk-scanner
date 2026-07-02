"""
opus_poc.py — Stage 4-2: Opus 최종 + PoC 생성

verified.jsonl 중 confirmed_likely / needs_poc 만 받아
Opus가 PoC를 작성하고 로컬 샌드박스에서 실행해 재현 여부를 확인한다.

안전 제약:
- 로컬 샌드박스(격리 tempdir)에서만 실행
- 네트워크 접근 코드는 실행 금지 (소켓/urllib/requests import 차단)
- 타임아웃 10초
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from pipeline.provider import Provider

_SYSTEM = """\
You are an expert security researcher. Generate a PoC script that demonstrates the
vulnerability by EXERCISING THE REAL TARGET PACKAGE — not a re-implementation.

CRITICAL REQUIREMENTS (violation = invalid PoC):
- The script MUST `import {package}` and call the REAL function named in the sink.
- DO NOT re-implement, emulate, or mock the vulnerable function. Calling your own
  copy of the logic proves nothing. You must trigger the bug in the actual installed code.
- If the real function rejects your malicious input (raises/sanitizes), that means the
  vulnerability does NOT exist — print "NOT_REPRODUCED" in that case.
- The script must be runnable with: python poc.py
- It must NOT make any network requests (no socket, urllib, requests, httpx)
- Keep it under 80 lines
- Print "VULNERABLE" ONLY if the real package actually produces the insecure output.
- Print "NOT_REPRODUCED" if the package blocks/sanitizes the input.

Output ONLY the Python script, no markdown fences."""

_BLOCKED_IMPORTS = {"socket", "urllib", "requests", "httpx", "aiohttp",
                    "paramiko", "ftplib", "smtplib", "telnetlib"}


def _has_network(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in getattr(node, "names", [])]
            module = getattr(node, "module", "") or ""
            if any(n.split(".")[0] in _BLOCKED_IMPORTS for n in names):
                return True
            if module.split(".")[0] in _BLOCKED_IMPORTS:
                return True
    return False


def _imports_target(code: str, package: str) -> bool:
    """PoC가 실제 대상 패키지를 import하는지 검증. 안 하면 자기충족 PoC."""
    pkg_root = package.replace("-", "_").split(".")[0]
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == pkg_root:
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module == pkg_root:
                return True
    return False


def _run_poc(code: str, timeout: int = 10, repo_path: str | None = None) -> tuple[bool, str]:
    """PoC 코드를 격리 tempdir에서 실행. 대상 레포를 PYTHONPATH에 주입."""
    with tempfile.TemporaryDirectory() as tmpdir:
        poc_file = Path(tmpdir) / "poc.py"
        poc_file.write_text(code, encoding="utf-8")

        env = dict(os.environ)
        if repo_path:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(Path(repo_path).resolve()) + os.pathsep + existing

        try:
            result = subprocess.run(
                [sys.executable, str(poc_file)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
                env=env,
            )
            output = result.stdout + result.stderr
            reproduced = "VULNERABLE" in output and "NOT_REPRODUCED" not in output
            return reproduced, output[:2000]
        except subprocess.TimeoutExpired:
            return False, "TIMEOUT"
        except Exception as e:
            return False, str(e)


def run_opus_poc(
    verified_path: str | Path,
    provider: Provider,
    confirmed_path: str | Path | None = None,
    fp_path: str | Path | None = None,
    max_candidates: int = 25,
    package: str = "",
    repo_path: str | None = None,
) -> tuple[Path, Path]:
    verified_path = Path(verified_path)
    data_dir = verified_path.parent
    if confirmed_path is None:
        confirmed_path = data_dir / "confirmed.jsonl"
    if fp_path is None:
        fp_path = data_dir / "false_positive.jsonl"

    confirmed_path = Path(confirmed_path)
    fp_path = Path(fp_path)

    # Sonnet이 긍정한 것만
    candidates = []
    with open(verified_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            verdict = rec.get("sonnet_verdict", {}).get("verdict", "rejected")
            if verdict in ("confirmed_likely", "needs_poc"):
                candidates.append(rec)

    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]

    model = "claude-opus-4-8"
    confirmed = []
    false_positives = []

    for i, cand in enumerate(candidates, 1):
        print(f"  [{i}/{len(candidates)}] Opus PoC — {cand.get('vuln_class','?')}")

        import_pkg = (package or "").replace("-", "_") or "the_target_package"
        user_msg = (
            f"Generate a PoC for this vulnerability.\n"
            f"You MUST `import {import_pkg}` and call its real function — do not reimplement it.\n\n"
            f"package to import: {import_pkg}\n"
            f"vuln_class: {cand.get('vuln_class','?')}\n"
            f"entrypoint: {cand.get('entrypoint','?')}\n"
            f"sink: {cand.get('sink','?')}\n"
            f"min_repro: {cand.get('min_repro','?')}\n\n"
            f"Sonnet verdict: {cand.get('sonnet_verdict',{}).get('reason','')}\n\n"
            f"Real source code of the function under test:\n"
            f"```python\n{cand.get('code','')[:3000]}\n```"
        )

        system_prompt = _SYSTEM.replace("{package}", import_pkg)
        resp = provider.chat(
            model=model,
            messages=[{"role": "user", "content": user_msg}],
            system=system_prompt,
            max_tokens=2048,
            cache_system=True,
        )

        poc_code = resp["content"].strip()
        if poc_code.startswith("```"):
            poc_code = poc_code.split("```", 2)[1]
            if poc_code.startswith("python"):
                poc_code = poc_code[6:]
            poc_code = poc_code.rsplit("```", 1)[0].strip()

        if _has_network(poc_code):
            print("    -> 네트워크 코드 감지 - 실행 거부")
            false_positives.append({**cand, "fp_reason": "network_code_in_poc"})
            continue

        # 대상 패키지를 실제로 import하는지 검증 (자기충족 PoC 차단)
        if package and not _imports_target(poc_code, package):
            print(f"    -> 대상 패키지({package}) import 없음 - 자기충족 PoC, 거짓양성")
            false_positives.append({**cand, "fp_reason": "poc_does_not_import_target",
                                    "poc_code": poc_code})
            continue

        reproduced, output = _run_poc(poc_code, repo_path=repo_path)
        print(f"    -> {'CONFIRMED' if reproduced else 'NOT REPRODUCED'}")

        record = {**cand, "poc_code": poc_code, "poc_output": output}
        if reproduced:
            confirmed.append(record)
        else:
            false_positives.append({**record, "fp_reason": "poc_not_reproduced"})

    confirmed_path.parent.mkdir(parents=True, exist_ok=True)
    with open(confirmed_path, "w", encoding="utf-8") as f:
        for r in confirmed:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(fp_path, "w", encoding="utf-8") as f:
        for r in false_positives:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"  확정: {len(confirmed)} | 거짓양성: {len(false_positives)}")
    print(f"  비용: {provider.summary()}")
    return confirmed_path, fp_path
