from __future__ import annotations

from scripts.fuzzer.incidents import compute_fingerprint
from scripts.fuzzer.models import FuzzerSignal


def test_same_shape_same_fingerprint():
    kwargs = dict(
        repo="valkey-io/valkey-fuzzer", workflow_file="fuzzer-run.yml",
        root_cause_category="split-brain",
        anomalies=[FuzzerSignal("Split-brain", "critical", "detected")],
    )
    assert compute_fingerprint(**kwargs) == compute_fingerprint(**kwargs)


def test_different_failures_differ():
    fp1 = compute_fingerprint(
        repo="r", workflow_file="w", root_cause_category="split-brain",
        anomalies=[FuzzerSignal("a", "critical", "x")],
    )
    fp2 = compute_fingerprint(
        repo="r", workflow_file="w", root_cause_category="crash",
        anomalies=[FuzzerSignal("b", "critical", "y")],
    )
    assert fp1 != fp2


def test_volatile_parts_normalized():
    fp1 = compute_fingerprint(
        repo="r", workflow_file="w", root_cause_category="crash",
        anomalies=[FuzzerSignal("crash", "critical", "node-1 at 0x7fff1234")],
    )
    fp2 = compute_fingerprint(
        repo="r", workflow_file="w", root_cause_category="crash",
        anomalies=[FuzzerSignal("crash", "critical", "node-5 at 0xdeadbeef")],
    )
    assert fp1 == fp2
