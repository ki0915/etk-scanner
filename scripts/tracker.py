"""
tracker.py — ETK-CAND numbering and duplicate management.

Usage:
  python scripts/tracker.py list
  python scripts/tracker.py new piccolo https://github.com/piccolo-orm/piccolo pypi
  python scripts/tracker.py check piccolo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CANDIDATES_DIR = Path(__file__).parent.parent / "candidates"
INDEX_FILE = CANDIDATES_DIR / ".tracker.json"


def _load_index() -> dict:
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return {"next_id": 1, "packages": {}}


def _save_index(index: dict) -> None:
    INDEX_FILE.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")


def _format_id(n: int) -> str:
    return f"ETK-CAND-{n:04d}"


def cmd_list(index: dict) -> None:
    if not index["packages"]:
        print("No candidates tracked yet.")
        return
    print(f"{'ID':<16} {'Package':<30} {'Ecosystem':<8} {'Status'}")
    print("-" * 70)
    for pkg, meta in sorted(index["packages"].items(), key=lambda x: x[1]["id"]):
        print(f"{meta['id']:<16} {pkg:<30} {meta['ecosystem']:<8} {meta.get('status', 'active')}")


def cmd_new(index: dict, package_name: str, github_url: str, ecosystem: str) -> None:
    pkg_key = package_name.lower()
    if pkg_key in index["packages"]:
        existing = index["packages"][pkg_key]
        print(f"Already tracked as {existing['id']}")
        return

    cand_id = _format_id(index["next_id"])
    folder_name = f"{cand_id}-{package_name}"
    cand_dir = CANDIDATES_DIR / folder_name

    index["packages"][pkg_key] = {
        "id": cand_id,
        "package": package_name,
        "github_url": github_url,
        "ecosystem": ecosystem,
        "status": "active",
        "folder": str(cand_dir),
    }
    index["next_id"] += 1
    _save_index(index)

    # Create directory scaffold
    (cand_dir / "repo").mkdir(parents=True, exist_ok=True)
    print(f"Created {cand_id} -> {cand_dir}")
    print(f"Next step: git clone {github_url} {cand_dir / 'repo'}")


def cmd_check(index: dict, package_name: str) -> None:
    pkg_key = package_name.lower()
    if pkg_key in index["packages"]:
        meta = index["packages"][pkg_key]
        print(f"DUPLICATE — already tracked as {meta['id']}")
        sys.exit(1)
    else:
        print(f"OK - '{package_name}' not yet in tracker")


def main() -> None:
    parser = argparse.ArgumentParser(description="ETK-CAND candidate tracker")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all tracked candidates")

    p_new = sub.add_parser("new", help="Register a new candidate")
    p_new.add_argument("package", help="Package name")
    p_new.add_argument("url", help="GitHub URL")
    p_new.add_argument("ecosystem", choices=["pypi", "npm", "cargo", "go"], default="pypi", nargs="?")

    p_check = sub.add_parser("check", help="Check if package is already tracked")
    p_check.add_argument("package", help="Package name to check")

    args = parser.parse_args()
    index = _load_index()

    if args.command == "list":
        cmd_list(index)
    elif args.command == "new":
        cmd_new(index, args.package, args.url, args.ecosystem)
    elif args.command == "check":
        cmd_check(index, args.package)


if __name__ == "__main__":
    main()
