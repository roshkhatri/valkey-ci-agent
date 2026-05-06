"""Data models for the fuzzer analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FuzzerSignal:
    """One anomalous or informational signal from a fuzzer run."""

    title: str
    severity: str  # "critical" or "warning"
    evidence: str


@dataclass
class FuzzerRunContext:
    """Collected evidence for one fuzzer workflow run."""

    repo: str
    workflow_file: str
    run_id: int
    run_url: str
    conclusion: str
    head_sha: str
    scenario_id: str | None = None
    seed: str | None = None
    tested_valkey_sha: str | None = None
    results: dict[str, Any] | None = None
    scenario_yaml: str | None = None
    structured_logs: dict[str, dict[str, Any]] = field(default_factory=dict)
    node_logs: dict[str, str] = field(default_factory=dict)
    raw_job_log: str | None = None


@dataclass
class FuzzerRunAnalysis:
    """Final analysis output for a fuzzer workflow run."""

    repo: str
    workflow_file: str
    run_id: int
    run_url: str
    conclusion: str
    head_sha: str
    overall_status: str  # "normal", "warning", "anomalous"
    triage_verdict: str
    summary: str
    anomalies: list[FuzzerSignal] = field(default_factory=list)
    normal_signals: list[str] = field(default_factory=list)
    scenario_id: str | None = None
    seed: str | None = None
    tested_valkey_sha: str | None = None
    root_cause_category: str | None = None
    reproduction_hint: str | None = None
    incident_fingerprint: str | None = None
    suggested_labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
