"""
analyze.py — CLI entry point for the AI pentesting pipeline.

Usage examples:

  # Full pipeline on an existing candidate
  python scripts/analyze.py ETK-CAND-0006 datasette

  # Screen only (cheap model, no deep validation)
  python scripts/analyze.py ETK-CAND-0006 datasette --screen-only

  # Custom repo path
  python scripts/analyze.py ETK-CAND-0006 datasette --repo path/to/repo

  # Save markdown report
  python scripts/analyze.py ETK-CAND-0006 datasette --output reports/2025/003/auto.md
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Make scripts/ importable when run from the project root
sys.path.insert(0, str(Path(__file__).parent))

from pipeline.models import Severity
from pipeline.orchestrator import run_pipeline


def _load_dotenv() -> None:
    """Load .env from project root if present (no external dependency needed)."""
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def _auto_repo_path(candidate_id: str) -> Path:
    """Guess the repo path from the candidate ID."""
    base = Path(__file__).parent.parent / "candidates"
    matches = sorted(base.glob(f"{candidate_id}*"))
    if not matches:
        raise FileNotFoundError(
            f"No candidate folder found for {candidate_id} under {base}.\n"
            "Clone the repo first or pass --repo explicitly."
        )
    return matches[0] / "repo"


def main() -> None:
    _load_dotenv()
    parser = argparse.ArgumentParser(
        description="AI pentesting pipeline: chunk → screen → validate"
    )
    parser.add_argument("candidate_id", help="ETK-CAND-XXXX identifier")
    parser.add_argument("package_name", help="Package name (for reporting)")
    parser.add_argument(
        "--repo",
        default=None,
        help="Path to cloned repo (auto-detected from candidates/ if omitted)",
    )
    parser.add_argument(
        "--screen-only",
        action="store_true",
        help="Run screener only, skip deep validation",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Confidence threshold for screening (default: SCREEN_THRESHOLD env or 6.0)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="low",
        help="Minimum severity to include in report",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write markdown report to this path",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    args = parser.parse_args()

    # Override threshold via CLI
    if args.threshold is not None:
        os.environ["SCREEN_THRESHOLD"] = str(args.threshold)

    # Resolve repo path
    if args.repo:
        repo_path = Path(args.repo)
    else:
        try:
            repo_path = _auto_repo_path(args.candidate_id)
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    if not repo_path.exists():
        print(f"Error: repo path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }

    report = run_pipeline(
        candidate_id=args.candidate_id,
        package_name=args.package_name,
        repo_path=repo_path,
        screen_only=args.screen_only,
        min_severity=severity_map[args.min_severity],
        verbose=not args.quiet,
    )

    # Write markdown report
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# Pipeline Report — {report.package_name}",
            f"**Candidate:** {report.candidate_id}",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Repo:** {report.repo_path}",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total chunks | {report.total_chunks} |",
            f"| Candidates (>= threshold) | {report.screened_count} |",
            f"| Confirmed vulnerabilities | {report.confirmed_count} |",
            "",
        ]
        for result in report.results:
            lines.append(result.to_markdown())
        out_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"\nReport written to: {out_path}")


if __name__ == "__main__":
    main()
