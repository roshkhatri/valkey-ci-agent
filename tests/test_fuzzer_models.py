"""Tests for fuzzer data models."""
from __future__ import annotations

from dataclasses import asdict

from scripts.fuzzer.models import FuzzerRunAnalysis, FuzzerRunContext, FuzzerSignal


def test_signal_construction():
    s = FuzzerSignal("crash", "critical", "segfault at server.c")
    assert s.title == "crash"


def test_context_defaults():
    ctx = FuzzerRunContext(repo="r", workflow_file="w", run_id=1, run_url="u",
                          conclusion="failure", head_sha="h")
    assert ctx.tested_valkey_sha is None
    assert ctx.node_logs == {}
    assert ctx.raw_job_log == ""


def test_analysis_roundtrip_via_asdict():
    a = FuzzerRunAnalysis(
        repo="r", workflow_file="w", run_id=1, run_url="u",
        conclusion="failure", head_sha="h", overall_status="anomalous",
        triage_verdict="likely-core-valkey-bug", summary="crash found",
        anomalies=[FuzzerSignal("crash", "critical", "x")],
    )
    d = asdict(a)
    assert d["run_id"] == 1
    assert d["anomalies"][0]["title"] == "crash"
