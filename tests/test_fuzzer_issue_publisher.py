"""Tests for fuzzer issue publisher (requires Python 3.9+)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from scripts.fuzzer.models import FuzzerRunAnalysis, FuzzerSignal

needs_39 = pytest.mark.skipif(sys.version_info < (3, 9), reason="requires 3.9+")

if sys.version_info >= (3, 9):
    from scripts.fuzzer.issue_publisher import (
        FuzzerIssuePublisher,
        _build_title,
        _render_body,
    )


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
def test_build_title_from_root_cause():
    assert _build_title(_analysis(root_cause_category="split-brain")) == "[fuzzer-run] Split Brain"


@needs_39
def test_build_title_from_anomaly():
    assert _build_title(_analysis()) == "[fuzzer-run] Node crash"


@needs_39
def test_render_body_contains_essentials():
    body = _render_body(_analysis(), "<!-- marker -->", occurrences=1)
    assert "<!-- marker -->" in body
    assert "occurrences:1" in body
    assert "Node crash" in body
    assert "crash found" in body


@needs_39
def test_creates_new_issue_when_search_returns_nothing(monkeypatch):
    monkeypatch.setenv("VALKEY_CI_AGENT_ALLOW_VALKEY_IO_PUBLISH", "1")
    mock_repo = MagicMock()
    mock_issue = MagicMock(number=1, html_url="https://x/issues/1")
    mock_repo.create_issue.return_value = mock_issue
    mock_gh = MagicMock()
    mock_gh.get_repo.return_value = mock_repo
    mock_gh.search_issues.return_value = iter([])

    action, _ = FuzzerIssuePublisher(mock_gh, retries=0).upsert_issue(
        "valkey-io/valkey-fuzzer", _analysis(),
    )
    assert action == "created"


@needs_39
def test_updates_existing_issue_on_search_hit(monkeypatch):
    monkeypatch.setenv("VALKEY_CI_AGENT_ALLOW_VALKEY_IO_PUBLISH", "1")
    marker = "<!-- valkey-ci-agent:fuzzer-issue:fp_test_12345678901 -->"
    existing = MagicMock(
        number=5, html_url="https://x/issues/5",
        body=f"{marker}\n<!-- valkey-ci-agent:occurrences:1 -->",
        title="[fuzzer-run] old",
    )
    mock_repo = MagicMock()
    mock_repo.get_issue.return_value = existing
    mock_gh = MagicMock()
    mock_gh.get_repo.return_value = mock_repo
    mock_gh.search_issues.return_value = [existing]

    action, _ = FuzzerIssuePublisher(mock_gh, retries=0).upsert_issue(
        "valkey-io/valkey-fuzzer", _analysis(),
    )
    assert action == "updated"
    existing.edit.assert_called_once()
    existing.create_comment.assert_called_once()


@needs_39
def test_updates_existing_with_none_body(monkeypatch):
    """Regression: existing issue with None body should not crash."""
    monkeypatch.setenv("VALKEY_CI_AGENT_ALLOW_VALKEY_IO_PUBLISH", "1")
    marker = "<!-- valkey-ci-agent:fuzzer-issue:fp_test_12345678901 -->"
    # Search result has the marker in body, but the reloaded issue has body=None.
    # (Unrealistic but tests the None-safety of the update path.)
    loaded = MagicMock(
        number=5, html_url="https://x/issues/5",
        body=None, title="[fuzzer-run] old",
    )
    mock_repo = MagicMock()
    mock_repo.get_issue.return_value = loaded
    mock_gh = MagicMock()
    mock_gh.get_repo.return_value = mock_repo
    search_result = MagicMock(number=5, body=f"{marker}\n")
    mock_gh.search_issues.return_value = [search_result]

    # Should not raise even though loaded.body is None.
    action, _ = FuzzerIssuePublisher(mock_gh, retries=0).upsert_issue(
        "valkey-io/valkey-fuzzer", _analysis(),
    )
    # The search verifies marker is in search_result.body, loads real issue,
    # then updates it. With None body, the occurrence marker gets appended.
    assert action == "updated"
    loaded.edit.assert_called_once()
