"""
quest.py — 로드맵을 퀘스트로: 다음 할 일 1개, 기계 판정, 즉시 보상

Usage:
  python scripts/quest.py              # 다음 퀘스트 1개 + 레벨 바
  python scripts/quest.py done T0-1    # verify 명령 실행 → PASS면 XP 지급
  python scripts/quest.py done T0-4 --force   # verify 없는 퀘스트 수동 완료
  python scripts/quest.py note "어디까지 했는지"
  python scripts/quest.py log          # 완료 기록
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).parent.parent
QUESTS = ROOT / "quests" / "quests.yaml"
PROGRESS = ROOT / "quests" / "progress.json"
ICON = {"build": "🔨", "break": "🗡️", "learn": "📚", "review": "🔍", "boss": "🏆"}


def _load() -> tuple[dict, dict]:
    spec = yaml.safe_load(QUESTS.read_text(encoding="utf-8"))
    prog = {"xp": 0, "done": {}, "note": ""}
    if PROGRESS.exists():
        prog.update(json.loads(PROGRESS.read_text(encoding="utf-8")))
    return spec, prog


def _save(prog: dict) -> None:
    PROGRESS.write_text(json.dumps(prog, indent=2, ensure_ascii=False), encoding="utf-8")


def _level(spec: dict, xp: int) -> tuple[int, str, int | None]:
    levels = spec["levels"]
    idx = max(i for i, lv in enumerate(levels) if xp >= lv["xp"])
    nxt = levels[idx + 1]["xp"] if idx + 1 < len(levels) else None
    return idx + 1, levels[idx]["title"], nxt


def _bar(spec: dict, xp: int) -> str:
    lv, title, nxt = _level(spec, xp)
    if nxt is None:
        return f"Lv.{lv} {title} | {xp} XP | 최고 레벨"
    base = spec["levels"][lv - 1]["xp"]
    filled = int(20 * (xp - base) / (nxt - base))
    return f"Lv.{lv} {title} [{'█' * filled}{'░' * (20 - filled)}] {xp}/{nxt} XP"


def cmd_next(spec: dict, prog: dict) -> None:
    if prog.get("note"):
        print(f"📌 지난번 멈춘 곳: {prog['note']}\n")
    print(_bar(spec, prog["xp"]))
    for q in spec["quests"]:
        if q["id"] in prog["done"]:
            continue
        print(f"\n{ICON.get(q['type'], '•')} [{q['id']}] {q['title']}")
        print(f"   ⏱  25분 블록 {q['blocks']}개 | 보상 {q['xp']} XP")
        print(f"   ▶ 첫 걸음: {q['first_step']}")
        if q.get("verify"):
            print(f"   ✔ 완료 판정: {q['verify']}")
        print(f"\n   끝나면: python scripts/quest.py done {q['id']}")
        return
    print("\n🎉 정의된 퀘스트를 모두 끝냈다. quests.yaml 에 다음 Phase를 추가하자.")


def cmd_done(spec: dict, prog: dict, qid: str, force: bool) -> int:
    q = next((x for x in spec["quests"] if x["id"] == qid), None)
    if q is None:
        print(f"[error] 없는 퀘스트: {qid}")
        return 2
    if qid in prog["done"]:
        print(f"이미 완료한 퀘스트다: {qid}")
        return 0
    if q.get("verify") and not force:
        print(f"판정 중: {q['verify']}")
        r = subprocess.run(q["verify"], shell=True, cwd=ROOT)
        if r.returncode != 0:
            print("\n❌ 아직 FAIL. 잃은 건 없다 — 에러 메시지가 다음 25분의 할 일이다.")
            return 1
    elif not q.get("verify") and not force:
        print("이 퀘스트는 자동 판정이 없다. 직접 확인했으면 --force 로 완료하자.")
        return 1
    before = _level(spec, prog["xp"])[0]
    prog["xp"] += q["xp"]
    prog["done"][qid] = datetime.now().strftime("%Y-%m-%d %H:%M")
    prog["note"] = ""
    _save(prog)
    print(f"\n✅ PASS — {q['title']}  (+{q['xp']} XP)")
    print(_bar(spec, prog["xp"]))
    lv, title, _ = _level(spec, prog["xp"])
    if lv > before:
        print(f"\n🆙 레벨 업! Lv.{lv} {title}")
    return 0


def cmd_log(spec: dict, prog: dict) -> None:
    print(_bar(spec, prog["xp"]))
    titles = {q["id"]: q for q in spec["quests"]}
    for qid, when in prog["done"].items():
        q = titles.get(qid, {"type": "", "title": "?", "xp": 0})
        print(f"  {when}  {ICON.get(q['type'], '•')} {qid}  +{q['xp']}  {q['title']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="ETK 퀘스트 트래커")
    sub = ap.add_subparsers(dest="cmd")
    d = sub.add_parser("done")
    d.add_argument("id")
    d.add_argument("--force", action="store_true")
    n = sub.add_parser("note")
    n.add_argument("text")
    sub.add_parser("log")
    args = ap.parse_args()

    spec, prog = _load()
    if args.cmd == "done":
        sys.exit(cmd_done(spec, prog, args.id, args.force))
    elif args.cmd == "note":
        prog["note"] = args.text
        _save(prog)
        print(f"📌 저장했다: {args.text}")
    elif args.cmd == "log":
        cmd_log(spec, prog)
    else:
        cmd_next(spec, prog)


if __name__ == "__main__":
    main()
