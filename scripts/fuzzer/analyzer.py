"""Fuzzer run analysis: deterministic pattern matching + Claude Code."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from scripts.ai.runtime import run_agent
from scripts.common.text_utils import strip_ansi
from scripts.fuzzer.artifacts import ArtifactClient
from scripts.fuzzer.incidents import compute_fingerprint
from scripts.fuzzer.models import FuzzerRunAnalysis, FuzzerRunContext, FuzzerSignal

logger = logging.getLogger(__name__)

# --- Pattern tables (core domain knowledge) ---

_ANOMALY_PATTERNS: list[tuple[str, str, str]] = [
    ("Node crash or assertion", "critical", r"ASSERTION FAILED|Assertion failed|BUG REPORT START|STACK TRACE"),
    ("Sanitizer failure", "critical", r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:"),
    ("Segfault", "critical", r"segmentation fault|signal 11"),
    ("OOM", "critical", r"Out Of Memory|Can't allocate|OOM command not allowed"),
    ("Failover timeout", "critical", r"Failover attempt expired|Manual failover timed out"),
    ("Split-brain or slot loss", "critical", r"split.?brain|slots still assigned to killed nodes"),
    ("RDB/AOF failure", "warning", r"Background saving error|Failed opening.*rdb|AOF rewrite.*failed"),
]

_BUG_INDICATOR_TITLES = {
    "Node crash or assertion", "Sanitizer failure", "Segfault",
    "Failover timeout", "Split-brain or slot loss",
}

_NORMAL_PATTERNS: list[tuple[str, str]] = [
    ("Failover completed", r"Failover election won|Failover auth granted"),
    ("Cluster recovered", r"Cluster state changed:.*ok"),
    ("RDB saved", r"Background saving terminated with success"),
    ("Replica synced", r"MASTER <-> REPLICA sync: Finished"),
]

_CHAOS_NOISE_PATTERNS: list[tuple[str, str]] = [
    ("CLUSTERDOWN", r"CLUSTERDOWN|Cluster state changed:.*fail"),
    ("Replication interrupted", r"MASTER aborted replication|Connection with (?:master|replica) lost"),
]

_SHA_KEYS = {"valkey_sha", "valkey_commit", "tested_valkey_sha", "server_sha", "target_sha"}
_SHA_RE = re.compile(r"[0-9a-f]{7,40}", re.IGNORECASE)
# GitHub Actions log prefix: "<job>\t<step>\t<iso8601>"
_LOG_PREFIX_RE = re.compile(r"^[^\t]+\t[^\t]+\t\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s?")


# --- Helpers ---

def _find_sha(data: Any) -> str | None:
    """Recursively search for a valkey commit SHA in nested dicts/lists."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in _SHA_KEYS and isinstance(v, str) and _SHA_RE.fullmatch(v):
                return v
            found = _find_sha(v)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_sha(item)
            if found:
                return found
    return None


def _scan_logs(context: FuzzerRunContext) -> tuple[list[FuzzerSignal], list[str]]:
    """Deterministic pattern matching on results.json and text logs."""
    anomalies: list[FuzzerSignal] = []
    normals: list[str] = []

    # Structured results.
    results = context.results or {}
    if results.get("success") is False:
        anomalies.append(FuzzerSignal(
            "Run failed", "critical",
            str(results.get("error_message") or "reported failure"),
        ))
    validation = results.get("final_validation")
    if isinstance(validation, dict):
        for name, check in (validation.get("checks") or {}).items():
            if not isinstance(check, dict):
                continue
            if check.get("success") is False:
                anomalies.append(FuzzerSignal(
                    f"{name} validation failed", "critical",
                    str(check.get("error") or "failed"),
                ))
            elif check.get("success") is True:
                normals.append(f"{name} passed")

    # Text logs.
    sources = list(context.node_logs.items())
    if not sources and context.raw_job_log:
        sources = [("job-log", context.raw_job_log)]

    for name, text in sources:
        cleaned = strip_ansi(text)
        for title, severity, pattern in _ANOMALY_PATTERNS:
            m = re.search(pattern, cleaned, re.I)
            if m:
                anomalies.append(FuzzerSignal(title, severity, f"{name}: {m.group(0)[:200]}"))
        for label, pattern in _NORMAL_PATTERNS:
            if re.search(pattern, cleaned, re.I):
                normals.append(f"{label} ({name})")
        for label, pattern in _CHAOS_NOISE_PATTERNS:
            if re.search(pattern, cleaned, re.I):
                normals.append(f"{label} ({name}) [chaos-expected]")

    return _dedupe_signals(anomalies), list(dict.fromkeys(normals))


def _dedupe_signals(signals: list[FuzzerSignal]) -> list[FuzzerSignal]:
    seen: set[tuple[str, str]] = set()
    out: list[FuzzerSignal] = []
    for s in signals:
        key = (s.title, s.evidence)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _load_artifacts(context: FuzzerRunContext, files: dict[str, bytes]) -> None:
    """Parse downloaded artifact files into the context."""
    for path, payload in files.items():
        name = path.rsplit("/", 1)[-1]
        text = payload.decode("utf-8", errors="replace")
        data: Any
        if name == "results.json":
            data = _safe_json(text)
            # The fuzzer wraps results as {"results": [...]}. Keep first entry.
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                context.results = data["results"][0] if data["results"] else None
            elif isinstance(data, dict):
                context.results = data
        elif name == "manifest.json":
            data = _safe_json(text)
            if isinstance(data, dict):
                context.tested_valkey_sha = _find_sha(data)
                sid = data.get("scenario_id")
                if sid:
                    context.scenario_id = str(sid)
                seed = data.get("seed")
                if seed is not None:
                    context.seed = str(seed)
        elif name == "scenario.yaml":
            context.scenario_yaml = text
        elif name.endswith(".json"):
            data = _safe_json(text)
            if isinstance(data, dict):
                context.structured_logs[name] = data
        elif name.endswith(".log"):
            context.node_logs[name] = text

    if not context.tested_valkey_sha:
        context.tested_valkey_sha = _find_sha(context.results)


def _safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _triage(anomalies: list[FuzzerSignal]) -> tuple[str, str]:
    """Determine overall_status and triage_verdict from anomalies."""
    if any(s.severity == "critical" for s in anomalies):
        status = "anomalous"
    elif anomalies:
        status = "warning"
    else:
        return "normal", "expected-chaos-noise"

    if {s.title for s in anomalies} & _BUG_INDICATOR_TITLES:
        return status, "likely-core-valkey-bug"
    return status, "possible-core-valkey-bug"


# --- Claude Code integration ---

_CLAUDE_PROMPT_TEMPLATE = """\
You analyze Valkey fuzzer workflow runs (chaos testing for Redis-compatible clusters).
Distinguish expected chaos behavior from real bugs. Be conservative — do not
invent anomalies without evidence.

Chaos-expected signals (NOT bugs): CLUSTERDOWN, replication link loss, cluster
state FAIL, server warnings, slot migration errors during node kills. These are
normal side-effects of killing nodes. Only flag them if they persist after the
cluster should have recovered.

Real bugs: crashes/assertions on nodes NOT targeted by chaos, sanitizer errors,
segfaults, permanent slot loss, split-brain, data inconsistency after recovery.

## Run info
Repository: {repo}
Run: {run_url}
Conclusion: {conclusion}
Tested Valkey SHA: {valkey_sha}
Scenario: {scenario_id} | Seed: {seed}

## Source code available
{source_note}

## Deterministic findings
{deterministic_summary}

## Task
Analyze this run. Read artifacts and source as needed. Return ONLY valid JSON:
{{
  "overall_status": "normal|warning|anomalous",
  "triage_verdict": "likely-core-valkey-bug|possible-core-valkey-bug|expected-chaos-noise|environmental-or-infra|needs-human-triage",
  "root_cause_category": "short-label or null",
  "summary": "2-3 sentence maintainer-facing summary explaining what happened AND why it indicates a bug (or why it's noise)",
  "anomalies": [{{"title": "...", "severity": "warning|critical", "evidence": "..."}}],
  "normal_signals": ["..."],
  "reproduction_hint": "command or null"
}}
"""


class _SourcesUnavailable(Exception):
    """Raised when source checkout fails critically."""


def _invoke_claude(context: FuzzerRunContext, anomalies: list[FuzzerSignal],
                   normals: list[str], workdir: Path) -> dict[str, Any]:
    """Write context to disk, clone sources, call Claude Code."""
    art_dir = workdir / "_artifacts"
    art_dir.mkdir()
    if context.results:
        (art_dir / "results.json").write_text(json.dumps(context.results, indent=2))
    if context.scenario_yaml:
        (art_dir / "scenario.yaml").write_text(context.scenario_yaml)
    for name, data in context.structured_logs.items():
        (art_dir / name).write_text(json.dumps(data, indent=2))
    for name, text in context.node_logs.items():
        (art_dir / name).write_text(text)
    if context.raw_job_log:
        (art_dir / "job-log.txt").write_text(context.raw_job_log)

    # Clone sources. If the tested SHA is unavailable, tell Claude so it
    # doesn't cite source line numbers with false confidence.
    valkey_ok = _shallow_clone("valkey-io/valkey", workdir / "valkey", context.tested_valkey_sha)
    fuzzer_ok = _shallow_clone(context.repo, workdir / "valkey-fuzzer", context.head_sha)

    source_lines = []
    if valkey_ok:
        source_lines.append(
            f"- valkey/ — Valkey source at commit {context.tested_valkey_sha or 'default branch'}. "
            "Grep for crash handlers, assertions."
        )
    else:
        source_lines.append(
            "- valkey/ — NOT AVAILABLE (clone failed). Do not cite source line numbers."
        )
    if fuzzer_ok:
        source_lines.append(
            "- valkey-fuzzer/ — Fuzzer source. Check validation logic if a check failed."
        )
    else:
        source_lines.append("- valkey-fuzzer/ — NOT AVAILABLE (clone failed).")
    source_lines.append("- _artifacts/ — Run artifacts (results.json, logs, scenario.yaml).")

    det_lines = [f"- [{a.severity}] {a.title}: {a.evidence}" for a in anomalies[:15]]
    det_lines.extend(f"- [normal] {n}" for n in normals[:10])

    prompt = _CLAUDE_PROMPT_TEMPLATE.format(
        repo=context.repo, run_url=context.run_url,
        conclusion=context.conclusion,
        valkey_sha=context.tested_valkey_sha or "unknown",
        scenario_id=context.scenario_id or "unknown",
        seed=context.seed or "unknown",
        source_note="\n".join(source_lines),
        deterministic_summary="\n".join(det_lines) or "None.",
    )

    result = run_agent("fuzzer_analysis_readonly", prompt, cwd=str(workdir))
    if result.returncode != 0:
        raise RuntimeError(f"Claude Code failed (rc={result.returncode}): {result.stderr[:300]}")

    return _parse_claude_response(result.stdout)


def _parse_claude_response(stdout: str) -> dict[str, Any]:
    """Extract JSON object from Claude Code output (stream-json or plain)."""
    # Find the last `result` event if stream-json, else use stdout directly.
    text = stdout
    for line in stdout.strip().splitlines():
        try:
            ev = json.loads(line)
            if isinstance(ev, dict) and ev.get("type") == "result" and "result" in ev:
                text = ev["result"]
        except ValueError:
            continue

    # Incremental JSON decode finds the first valid object, handling prose
    # before or after it correctly (unlike a greedy regex).
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(text[start:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        start = text.find("{", start + 1)
    raise ValueError("No JSON object in Claude response")


def _shallow_clone(repo: str, dest: Path, sha: str | None) -> bool:
    """Clone and optionally check out a specific SHA. Returns True on success."""
    if sha and not _SHA_RE.fullmatch(sha):
        logger.warning("Rejecting non-SHA value for %s: %r", repo, sha)
        return False

    args = ["git", "clone", "--filter=blob:none"]
    if not sha:
        args.extend(["--depth", "1"])
    args.extend([f"https://github.com/{repo}.git", str(dest)])

    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        logger.warning("Clone %s failed: %s", repo, r.stderr[:200])
        return False
    if not sha:
        return True

    fetch = subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", sha],
        cwd=str(dest), capture_output=True, text=True, timeout=60,
    )
    if fetch.returncode != 0:
        logger.warning("git fetch %s in %s failed: %s", sha, repo, fetch.stderr[:200])
        return False
    checkout = subprocess.run(
        ["git", "checkout", sha],
        cwd=str(dest), capture_output=True, text=True, timeout=30,
    )
    if checkout.returncode != 0:
        logger.warning("git checkout %s in %s failed: %s", sha, repo, checkout.stderr[:200])
        return False
    return True


# --- Main analyzer class ---

class FuzzerRunAnalyzer:
    """Analyzes fuzzer workflow runs: pattern matching + Claude Code."""

    def __init__(self, github_client: Any, *, github_token: str,
                 artifact_client: ArtifactClient | None = None) -> None:
        self._gh = github_client
        self._client = artifact_client or ArtifactClient(github_client, token=github_token)

    def analyze(self, repo: str, run_id: int, *, workflow_file: str) -> FuzzerRunAnalysis:
        gh_repo = self._gh.get_repo(repo)
        run = gh_repo.get_workflow_run(run_id)
        context = FuzzerRunContext(
            repo=repo, workflow_file=workflow_file, run_id=run_id,
            run_url=run.html_url,
            conclusion=str(run.conclusion or ""),
            head_sha=str(run.head_sha or ""),
        )

        # Fetch artifacts.
        artifacts = self._client.list_run_artifacts(repo, run_id)
        bundle = next((a for a in artifacts if a.name.startswith("fuzzer-run-artifacts") and not a.expired), None)
        if bundle:
            _load_artifacts(context, self._client.download_artifact(repo, bundle.artifact_id))

        # Fallback: raw run logs.
        if not context.results and not context.node_logs:
            log_files = self._client.download_run_logs(repo, run_id)
            parts = [payload.decode("utf-8", errors="replace")
                     for path, payload in sorted(log_files.items())
                     if path.endswith((".txt", ".log"))]
            if parts:
                context.raw_job_log = "\n".join(parts)

        # Extract scenario/seed from job log if missing from artifacts.
        if context.raw_job_log and (not context.scenario_id or not context.seed):
            stripped = _LOG_PREFIX_RE.sub("", context.raw_job_log)
            if not context.scenario_id:
                m = re.search(r"Scenario:\s*(\S+)", stripped)
                if m:
                    context.scenario_id = m.group(1)
            if not context.seed:
                m = re.search(r"Seed:\s*(\S+)", stripped)
                if m:
                    context.seed = m.group(1)

        # Phase 1: deterministic pattern matching.
        anomalies, normals = _scan_logs(context)

        # Phase 2: Claude Code deep analysis. On failure, fall back to
        # deterministic-only triage and mark the run as needing human review.
        model_payload: dict[str, Any] = {}
        claude_error: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="fuzzer-") as td:
                model_payload = _invoke_claude(context, anomalies, normals, Path(td))
        except Exception as exc:
            claude_error = str(exc)
            logger.warning("Claude analysis failed for run %s: %s", run_id, exc)

        # Merge Claude's anomalies and dedupe.
        for raw in _listlike(model_payload.get("anomalies")):
            if isinstance(raw, dict) and raw.get("title"):
                anomalies.append(FuzzerSignal(
                    str(raw["title"]), str(raw.get("severity") or "warning"),
                    str(raw.get("evidence", "")),
                ))
        anomalies = _dedupe_signals(anomalies)
        normals.extend(s for s in _listlike(model_payload.get("normal_signals")) if isinstance(s, str))
        normals = list(dict.fromkeys(normals))

        # Triage: deterministic + Claude, ratcheting toward stronger verdicts.
        overall_status, triage_verdict = _triage(anomalies)
        claude_status = model_payload.get("overall_status")
        if claude_status == "anomalous":
            overall_status = "anomalous"
        if model_payload.get("triage_verdict") == "likely-core-valkey-bug":
            triage_verdict = "likely-core-valkey-bug"
        # If Claude failed and we have no deterministic anomalies, we can't
        # confidently say "normal" — flag for human review.
        if claude_error and not anomalies:
            overall_status = "warning"
            triage_verdict = "needs-human-triage"

        summary = str(model_payload.get("summary") or "").strip()
        if not summary:
            if claude_error:
                summary = f"Run {run_id}: Claude analysis unavailable ({claude_error[:100]}); deterministic review found {len(anomalies)} anomalies."
            elif anomalies:
                summary = f"Run {run_id}: {len(anomalies)} anomalies detected ({anomalies[0].title})"
            else:
                summary = f"Run {run_id}: no anomalies detected"

        root_cause = model_payload.get("root_cause_category")
        if not isinstance(root_cause, str):
            root_cause = None

        fingerprint = compute_fingerprint(
            repo=repo, workflow_file=workflow_file,
            root_cause_category=root_cause, anomalies=anomalies,
        )

        hint = model_payload.get("reproduction_hint")
        if not isinstance(hint, str) or not hint:
            hint = f"valkey-fuzzer cluster --seed {context.seed}" if context.seed else None

        labels = ["possible-valkey-bug"] if triage_verdict in {
            "likely-core-valkey-bug", "possible-core-valkey-bug",
        } else []

        return FuzzerRunAnalysis(
            repo=repo, workflow_file=workflow_file, run_id=run_id,
            run_url=context.run_url, conclusion=context.conclusion,
            head_sha=context.head_sha, overall_status=overall_status,
            triage_verdict=triage_verdict, summary=summary,
            anomalies=anomalies, normal_signals=normals,
            scenario_id=context.scenario_id, seed=context.seed,
            tested_valkey_sha=context.tested_valkey_sha,
            root_cause_category=root_cause, reproduction_hint=hint,
            incident_fingerprint=fingerprint, suggested_labels=labels,
        )


def _listlike(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
