"""Tests for fuzzer main CLI (requires Python 3.9+)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

needs_39 = pytest.mark.skipif(sys.version_info < (3, 9), reason="requires 3.9+")

if sys.version_info >= (3, 9):
    import scripts.fuzzer.main as fuzzer_main_mod


@needs_39
def test_requires_token(capsys, monkeypatch):
    monkeypatch.delenv("TARGET_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        fuzzer_main_mod.main([])
    err = capsys.readouterr().err
    assert "target-token" in err or "TARGET_TOKEN" in err


@needs_39
def test_dry_run(monkeypatch):
    monkeypatch.setenv("TARGET_TOKEN", "fake")
    mock_gh_cls = MagicMock()
    mock_workflow = MagicMock()
    mock_workflow.get_runs.return_value = iter([])
    mock_repo = MagicMock()
    mock_repo.get_workflow.return_value = mock_workflow
    mock_gh_cls.return_value.get_repo.return_value = mock_repo

    with patch.object(fuzzer_main_mod, "Github", mock_gh_cls):
        rc = fuzzer_main_mod.main(["--dry-run"])
    assert rc == 0
