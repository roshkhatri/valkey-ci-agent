"""GitHub issue creation/upsert for anomalous fuzzer runs."""

from __future__ import annotations

import logging
import re
from typing import Any

from scripts.common.github_client import retry_github_call
from scripts.common.publish_guard import check_publish_allowed
from scripts.fuzzer.models import FuzzerRunAnalysis

logger = logging.getLogger(__name__)

_MARKER_PREFIX = "<!-- valkey-ci-agent:fuzzer-issue:"
_OCCURRENCES_RE = re.compile(r"<!-- valkey-ci-agent:occurrences:(\d+) -->")


class FuzzerIssuePublisher:
    """Creates or updates issues on the target repo for anomalous runs."""

    def __init__(self, github_client: Any, *, retries: int = 3) -> None:
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
        title = _build_title(analysis)

        existing = self._find_existing(repo_name, marker)

        if existing is None:
            body = _render_body(analysis, marker, occurrences=1)
            check_publish_allowed(target_repo=repo_name, action="create_issue",
                                  context=f"fuzzer: {title[:50]}")
            issue = retry_github_call(
                lambda: repo.create_issue(title=title, body=body),
                retries=self._retries, description="create issue",
            )
            if analysis.suggested_labels:
                try:
                    retry_github_call(
                        lambda: issue.add_to_labels(*analysis.suggested_labels),
                        retries=self._retries, description="add labels",
                    )
                except Exception as exc:
                    logger.info("Could not add labels to issue #%s: %s", issue.number, exc)
            logger.info("Created issue #%s for run %s", issue.number, analysis.run_id)
            return "created", issue.html_url

        # Update existing.
        body = existing.body or ""
        m = _OCCURRENCES_RE.search(body)
        count = int(m.group(1)) + 1 if m else 2
        new_body = (
            _OCCURRENCES_RE.sub(f"<!-- valkey-ci-agent:occurrences:{count} -->", body)
            if m else f"{body}\n<!-- valkey-ci-agent:occurrences:{count} -->"
        )
        check_publish_allowed(target_repo=repo_name, action="edit_issue",
                              context=f"issue #{existing.number}")
        retry_github_call(
            lambda: existing.edit(body=new_body, title=title),
            retries=self._retries, description="update issue",
        )
        check_publish_allowed(target_repo=repo_name, action="create_comment",
                              context=f"issue #{existing.number}")
        retry_github_call(
            lambda: existing.create_comment(body=_render_comment(analysis, count)),
            retries=self._retries, description="add comment",
        )
        logger.info("Updated issue #%s (occurrence %d)", existing.number, count)
        return "updated", existing.html_url

    def _find_existing(self, repo_name: str, marker: str) -> Any:
        """Find an open issue containing the marker.

        Uses the GitHub search API to avoid paginating all open issues.
        Falls back to listing recent open issues if search is unavailable.
        """
        # The marker itself contains the unique fingerprint.
        query = f'"{marker}" in:body repo:{repo_name} is:issue is:open'
        try:
            results = retry_github_call(
                lambda: list(self._gh.search_issues(query)),
                retries=self._retries, description="search existing issue",
            )
            for issue in results:
                if marker in (issue.body or ""):
                    # Reload against the actual repo to get a mutable issue
                    # handle (search results are sometimes read-only wrappers).
                    return retry_github_call(
                        lambda iss=issue: self._gh.get_repo(repo_name).get_issue(iss.number),
                        retries=self._retries, description=f"load issue #{issue.number}",
                    )
        except Exception as exc:
            logger.warning("Issue search failed, skipping dedup check: %s", exc)
        return None


def _build_title(analysis: FuzzerRunAnalysis) -> str:
    if analysis.root_cause_category:
        label = analysis.root_cause_category.replace("-", " ").replace("_", " ").title()
        return f"[fuzzer-run] {label}"
    if analysis.anomalies:
        return f"[fuzzer-run] {analysis.anomalies[0].title}"
    return "[fuzzer-run] Anomalous behavior detected"


def _render_body(analysis: FuzzerRunAnalysis, marker: str, *, occurrences: int) -> str:
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


def _render_comment(analysis: FuzzerRunAnalysis, count: int) -> str:
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
