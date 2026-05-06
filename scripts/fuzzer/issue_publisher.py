"""GitHub issue creation/upsert for anomalous fuzzer runs."""

from __future__ import annotations

import logging
import re

from scripts.common.github_client import retry_github_call
from scripts.common.publish_guard import check_publish_allowed
from scripts.fuzzer.models import FuzzerRunAnalysis

logger = logging.getLogger(__name__)

_MARKER_PREFIX = "<!-- valkey-ci-agent:fuzzer-issue:"
_OCCURRENCES_RE = re.compile(r"<!-- valkey-ci-agent:occurrences:(\d+) -->")


class FuzzerIssuePublisher:
    """Creates or updates issues on the target repo for anomalous runs."""

    def __init__(self, github_client: object, *, retries: int = 3) -> None:
        self._gh = github_client
        self._retries = retries

    def upsert_issue(self, repo_name: str, analysis: FuzzerRunAnalysis) -> tuple[str, str]:
        """Create or update an issue. Returns (action, url)."""
        repo = retry_github_call(
            lambda: self._gh.get_repo(repo_name),
            retries=self._retries, description=f"get repo {repo_name}",
        )
        fp = analysis.incident_fingerprint or "unknown"
        marker = f"{_MARKER_PREFIX}{fp} -->"
        title = self._build_title(analysis)

        # Search for existing issue with same fingerprint.
        existing = None
        for issue in retry_github_call(
            lambda: list(repo.get_issues(state="open")),
            retries=self._retries, description="list issues",
        ):
            if getattr(issue, "pull_request", None):
                continue
            if marker in (issue.body or ""):
                existing = issue
                break

        if existing is None:
            body = self._render_body(analysis, marker, occurrences=1)
            check_publish_allowed(target_repo=repo_name, action="create_issue",
                                  context=f"fuzzer: {title[:50]}")
            issue = retry_github_call(
                lambda: repo.create_issue(title=title, body=body),
                retries=self._retries, description="create issue",
            )
            logger.info("Created issue #%s for run %s", issue.number, analysis.run_id)
            return "created", issue.html_url

        # Update existing.
        m = _OCCURRENCES_RE.search(existing.body or "")
        count = int(m.group(1)) + 1 if m else 2
        new_body = _OCCURRENCES_RE.sub(
            f"<!-- valkey-ci-agent:occurrences:{count} -->", existing.body,
        )
        check_publish_allowed(target_repo=repo_name, action="edit_issue",
                              context=f"issue #{existing.number}")
        retry_github_call(
            lambda: existing.edit(body=new_body, title=title),
            retries=self._retries, description="update issue",
        )
        comment = self._render_comment(analysis, count)
        check_publish_allowed(target_repo=repo_name, action="create_comment",
                              context=f"issue #{existing.number}")
        retry_github_call(
            lambda: existing.create_comment(body=comment),
            retries=self._retries, description="add comment",
        )
        logger.info("Updated issue #%s (occurrence %d)", existing.number, count)
        return "updated", existing.html_url

    def _build_title(self, analysis: FuzzerRunAnalysis) -> str:
        if analysis.root_cause_category:
            label = analysis.root_cause_category.replace("-", " ").replace("_", " ").title()
            return f"[fuzzer-run] {label}"
        if analysis.anomalies:
            return f"[fuzzer-run] {analysis.anomalies[0].title}"
        return "[fuzzer-run] Anomalous behavior detected"

    def _render_body(self, analysis: FuzzerRunAnalysis, marker: str, *, occurrences: int) -> str:
        lines = [
            marker,
            f"<!-- valkey-ci-agent:occurrences:{occurrences} -->",
            "",
            "## Fuzzer Run Analysis",
            "",
            f"**Verdict**: {analysis.triage_verdict}",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Run | [{analysis.run_id}]({analysis.run_url}) |",
            f"| Status | `{analysis.overall_status}` |",
            f"| Conclusion | `{analysis.conclusion}` |",
            f"| Scenario | `{analysis.scenario_id or 'unknown'}` |",
            f"| Seed | `{analysis.seed or 'unknown'}` |",
        ]
        if analysis.tested_valkey_sha:
            lines.append(f"| Valkey SHA | `{analysis.tested_valkey_sha}` |")
        lines.extend(["", "### Summary", "", analysis.summary])
        if analysis.anomalies:
            lines.extend(["", "### Findings", ""])
            for a in analysis.anomalies[:10]:
                lines.append(f"- **[{a.severity}]** {a.title}: {a.evidence}")
        if analysis.reproduction_hint:
            lines.extend(["", f"**Reproduce**: `{analysis.reproduction_hint}`"])
        lines.extend(["", "---", "*valkey-ci-agent*"])
        return "\n".join(lines)

    def _render_comment(self, analysis: FuzzerRunAnalysis, count: int) -> str:
        lines = [
            f"## Occurrence #{count}",
            "",
            f"Run [{analysis.run_id}]({analysis.run_url}) | "
            f"`{analysis.overall_status}` | `{analysis.triage_verdict}`",
            "",
            analysis.summary,
        ]
        if analysis.anomalies:
            lines.append("")
            for a in analysis.anomalies[:5]:
                lines.append(f"- **[{a.severity}]** {a.title}: {a.evidence}")
        return "\n".join(lines)
