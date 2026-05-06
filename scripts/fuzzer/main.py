"""Monitor scheduled Valkey fuzzer workflow runs."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from github import Auth, Github

from scripts.fuzzer.analyzer import FuzzerRunAnalyzer
from scripts.fuzzer.artifacts import ArtifactClient
from scripts.fuzzer.issue_publisher import FuzzerIssuePublisher

logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    """Analyze recent fuzzer runs and optionally publish issues."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-repo", default="valkey-io/valkey-fuzzer")
    parser.add_argument("--workflow-file", default="fuzzer-run.yml")
    parser.add_argument("--event", default="schedule")
    parser.add_argument("--target-token", default=None)
    parser.add_argument("--max-runs", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    token = args.target_token or os.environ.get("TARGET_TOKEN", "")
    if not token:
        parser.error("--target-token or TARGET_TOKEN env var is required")

    gh = Github(auth=Auth.Token(token))
    client = ArtifactClient(gh, token=token)
    analyzer = FuzzerRunAnalyzer(gh, github_token=token, artifact_client=client)
    publisher = FuzzerIssuePublisher(gh)

    runs = client.list_recent_runs(
        args.target_repo, args.workflow_file,
        event=args.event, max_runs=args.max_runs,
    )

    results: list[dict[str, Any]] = []
    for run in runs:
        entry: dict[str, Any] = {
            "run_id": run.id,
            "conclusion": run.conclusion or "",
            "html_url": run.html_url,
        }

        if args.dry_run:
            entry["action"] = "would-analyze"
            results.append(entry)
            continue

        try:
            analysis = analyzer.analyze(
                args.target_repo, run.id, workflow_file=args.workflow_file,
            )
            entry["action"] = "analyzed"
            entry["status"] = analysis.overall_status
            entry["verdict"] = analysis.triage_verdict
            entry["summary"] = analysis.summary

            if analysis.overall_status == "anomalous":
                action, url = publisher.upsert_issue(args.target_repo, analysis)
                entry["issue_action"] = action
                entry["issue_url"] = url
        except Exception as exc:
            entry["action"] = "error"
            entry["error"] = str(exc)
            logger.warning("Failed to analyze run %s: %s", run.id, exc)

        results.append(entry)

    output = {"target_repo": args.target_repo, "dry_run": args.dry_run, "runs": results}
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
