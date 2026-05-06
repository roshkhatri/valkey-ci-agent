"""Tests for fuzzer issue publisher (requires Python 3.9+)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from scripts.fuzzer.models import FuzzerRunAnalysis, FuzzerSignal

needs_39 = pytest.mark.skipif(sys.version_info < (3, 9), reason="requires 3.9+")

if sys.version_info >= (3, 9):
    from scripts.fuzzer.issue_publisher import FuzzerIssuePublisher


def _analysis(**kw) -> FuzzerRunAnalysis:
    defaults = dict(
        repo="valkey-io/valkey-fuzzer", workflow_file="fuzzer-run.yml",
        run_id=100, run_url="https://github.com/r/actions/runs/100",
        conclusion="failure", head_sha="abc", overall_status="anomalous",
        triage_verdict="likely-core-valkey-bug", summary="crash found",
        anomalies=[FuzzerSignal("Node crash", "critical", "segfault")],
        incident_fingerprint="fp_test_12345678901",
    )
    defaults.update(kw)
    return FuzzerRunAnalysis(**defaults)


@needs_39
def test_creates_new_issue(monkeypatch):
    monkeypatch.setenv("VALKEY_CI_AGENT_ALLOW_VALKEY_IO_PUBLISH", "1")
    mock_repo = MagicMock()
    mock_repo.get_issues.return_value = []
    mock_issue = MagicMock(number=1, html_url="https://x/issues/1")
    mock_issue.get_labels.return_value = []
    mock_repo.create_issue.return_value = mock_issue
    mock_gh = MagicMock()
    mock_gh.get_repo.return_value = mock_repo

    action, url = FuzzerIssuePublisher(mock_gh, retries=0).upsert_issue(
        "valkey-io/valkey-fuzzer", _analysis(),
    )
    assert action == "created"
    mock_repo.create_issue.assert_called_once()


@needs_39
def test_updates_existing_issue(monkeypatch):
    monkeypatch.setenv("VALKEY_CI_AGENT_ALLOW_VALKEY_IO_PUBLISH", "1")
    existing = MagicMock(
        number=5, html_url="https://x/issues/5", pull_request=None,
        body="<!-- valkey-ci-agent:fuzzer-issue:fp_test_12345678901 -->\n<!-- valkey-ci-agent:occurrences:1 -->",
        title="[fuzzer-run] old",
    )
    mock_repo = MagicMock()
    mock_repo.get_issues.return_value = [existing]
    mock_gh = MagicMock()
    mock_gh.get_repo.return_value = mock_repo

    action, _ = FuzzerIssuePublisher(mock_gh, retries=0).upsert_issue(
        "valkey-io/valkey-fuzzer", _analysis(),
    )
    assert action == "updated"
    existing.edit.assert_called_once()
    existing.create_comment.assert_called_once()
