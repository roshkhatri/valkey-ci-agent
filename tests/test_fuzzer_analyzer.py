"""Tests for fuzzer analyzer (requires Python 3.9+ for full import)."""
from __future__ import annotations

import sys

import pytest

from scripts.fuzzer.models import FuzzerRunContext, FuzzerSignal

needs_39 = pytest.mark.skipif(sys.version_info < (3, 9), reason="requires 3.9+")

if sys.version_info >= (3, 9):
    from scripts.fuzzer.analyzer import (
        _clean_log,
        _find_valkey_sha,
        _load_artifacts,
        _scan_logs,
        _triage,
    )


@needs_39
def test_clean_log():
    raw = "x\ty\t2024-01-01T00:00:00.000Z \x1b[31mERROR\x1b[0m msg"
    assert "ERROR msg" in _clean_log(raw)
    assert "\x1b" not in _clean_log(raw)


@needs_39
def test_scan_logs_detects_crash():
    ctx = FuzzerRunContext(repo="r", workflow_file="w", run_id=1, run_url="u",
                          conclusion="failure", head_sha="h")
    ctx.raw_job_log = "ASSERTION FAILED at server.c:123"
    anomalies, _ = _scan_logs(ctx)
    assert any("crash" in a.title.lower() or "assertion" in a.title.lower() for a in anomalies)


@needs_39
def test_scan_logs_detects_normal():
    ctx = FuzzerRunContext(repo="r", workflow_file="w", run_id=1, run_url="u",
                          conclusion="success", head_sha="h")
    ctx.node_logs = {"n.log": "Failover election won"}
    anomalies, normals = _scan_logs(ctx)
    assert len(anomalies) == 0
    assert any("Failover" in n for n in normals)


@needs_39
def test_scan_logs_structured_results():
    ctx = FuzzerRunContext(repo="r", workflow_file="w", run_id=1, run_url="u",
                          conclusion="failure", head_sha="h")
    ctx.results = {
        "success": False, "error_message": "failed",
        "final_validation": {"checks": {"slot_coverage": {"success": False, "error": "lost slots"}}},
    }
    anomalies, _ = _scan_logs(ctx)
    assert any("slot" in a.title.lower() for a in anomalies)


@needs_39
def test_find_valkey_sha():
    assert _find_valkey_sha({"valkey_sha": "abc1234"}) == "abc1234"
    assert _find_valkey_sha({"nested": {"tested_valkey_sha": "def5678"}}) == "def5678"
    assert _find_valkey_sha({"unrelated": "data"}) is None


@needs_39
def test_load_artifacts():
    ctx = FuzzerRunContext(repo="r", workflow_file="w", run_id=1, run_url="u",
                          conclusion="failure", head_sha="h")
    _load_artifacts(ctx, {
        "manifest.json": b'{"scenario_id": "chaos-1", "seed": 42, "valkey_sha": "deadbeef1234567"}',
        "results.json": b'{"results": [{"success": false}]}',
        "node-1.log": b"log output",
    })
    assert ctx.scenario_id == "chaos-1"
    assert ctx.seed == "42"
    assert ctx.tested_valkey_sha == "deadbeef1234567"
    assert "node-1.log" in ctx.node_logs


@needs_39
def test_triage_normal():
    status, verdict = _triage([])
    assert status == "normal"
    assert verdict == "expected-chaos-noise"


@needs_39
def test_triage_critical():
    status, verdict = _triage([FuzzerSignal("Node crash or assertion", "critical", "x")])
    assert status == "anomalous"
    assert verdict == "likely-core-valkey-bug"


@needs_39
def test_triage_warning():
    status, verdict = _triage([FuzzerSignal("something", "warning", "x")])
    assert status == "warning"
    assert verdict == "possible-core-valkey-bug"
