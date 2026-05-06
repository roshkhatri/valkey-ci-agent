"""Fuzzer run analysis: deterministic pattern matching + Claude Code."""

from __future__ import annotations

import json
import logging
import re
import shutil
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
_LOG_PREFIX_RE = re.compile(r"^[^\t]+\t[^\t]+\t\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s?")


# --- Helpers ---

def _find_valkey_sha(data: Any) -> str | None:
    """Recursively search for a valkey commit SHA in nested dicts/lists."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in _SHA_KEYS and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{7,40}", v, re.I):
                return v
            found = _find_valkey_sha(v)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_valkey_sha(item)
            if found:
                return found
    return None


def _clean_log(raw: str) -> str:
    """Strip GitHub Actions timestamp prefixes and ANSI codes."""
    lines = [strip_ansi(_LOG_PREFIX_RE.sub("", line)) for line in raw.splitlines()]
    return "\n".join(lines)


def _scan_logs(context: FuzzerRunContext) -> tuple[list[FuzzerSignal], list[str]]:
    """Run deterministic pattern matching on all available logs."""
    anomalies: list[FuzzerSignal] = []
    normals: list[str] = []

    # Check structured results first.
    results = context.results or {}
    if results.get("success") is False:
        anomalies.append(FuzzerSignal(
            "Run failed", "critical",
            str(results.get("error_message") or "reported failure"),
        ))
    validation = results.get("final_validation")
    if isinstance(validation, dict):
        for name, check in (validation.get("checks") or {}).items():
            if isinstance(check, dict):
                if check.get("success") is False:
                    anomalies.append(FuzzerSignal(
                        f"{name} validation failed", "critical",
                        str(check.get("error") or "failed"),
                    ))
                elif check.get("success") is True:
                    normals.append(f"{name} passed")

    # Scan text logs.
    sources: list[tuple[str, str]] = list(context.node_logs.items())
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

    # Dedupe.
    seen: set[tuple[str, str]] = set()
    deduped: list[FuzzerSignal] = []
    for s in anomalies:
        key = (s.title, s.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped, list(dict.fromkeys(normals))


def _load_artifacts(context: FuzzerRunContext, files: dict[str, bytes]) -> None:
    """Parse downloaded artifact files into the context."""
    for path, payload in files.items():
        name = path.rsplit("/", 1)[-1]
        text = payload.decode("utf-8", errors="replace")
        if name == "results.json":
            data = _json(text)
            # Handle wrapped format: {"results": [...]}
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                context.results = data["results"][0] if data["results"] else None
            else:
                context.results = data
        elif name == "manifest.json":
            manifest = _json(text)
            context.tested_valkey_sha = context.tested_valkey_sha or _find_valkey_sha(manifest)
            if isinstance(manifest, dict):
                sid = manifest.get("scenario_id")
                if sid:
                    context.scenario_id = context.scenario_id or str(sid)
                seed = manifest.get("seed")
                if seed is not None:
                    context.seed = context.seed or str(seed)
        elif name == "scenario.yaml":
            context.scenario_yaml = text
        elif name.endswith(".json"):
            data = _json(text)
            if isinstance(data, dict):
                context.structured_logs[name] = data
        elif name.endswith(".log"):
            context.node_logs[name] = text

    context.tested_valkey_sha = context.tested_valkey_sha or _find_valkey_sha(context.results)


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _triage(anomalies: list[FuzzerSignal]) -> tuple[str, str]:
    """Determine overall_status and triage_verdict from anomalies."""
    if any(s.severity == "critical" for s in anomalies):
        status = "anomalous"
    elif anomalies:
        status = "warning"
    else:
        return "normal", "expected-chaos-noise"

    critical_titles = {s.title for s in anomalies if s.severity == "critical"}
    bug_indicators = {"Node crash or assertion", "Sanitizer failure", "Segfault",
                      "Failover timeout", "Split-brain or slot loss"}
    if critical_titles & bug_indicators:
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
- valkey/ — Valkey source at the tested commit. Grep for crash handlers, assertions.
- valkey-fuzzer/ — Fuzzer source. Check validation logic if a check failed.
- _artifacts/ — Run artifacts (results.json, logs, scenario.yaml).

## Deterministic findings
{deterministic_summary}

## Task
Analyze this run. Read artifacts and source as needed. Return ONLY valid JSON:
{{
  "overall_status": "normal|warning|anomalous",
  "triage_verdict": "likely-core-valkey-bug|possible-core-valkey-bug|expected-chaos-noise|environmental-or-infra|needs-human-triage",
  "root_cause_category": "short-label or null",
  "summary": "one-line maintainer-facing summary",
  "anomalies": [{{"title": "...", "severity": "warning|critical", "evidence": "..."}}],
  "normal_signals": ["..."],
  "reproduction_hint": "command or null"
}}
"""


def _invoke_claude(context: FuzzerRunContext, anomalies: list[FuzzerSignal],
                   normals: list[str], workdir: Path) -> dict[str, Any]:
    """Write context to disk, clone sources, call Claude Code."""
    # Write artifacts.
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

    # Clone valkey source at tested commit.
    _shallow_clone("valkey-io/valkey", workdir / "valkey", context.tested_valkey_sha)
    # Clone fuzzer source at workflow head.
    _shallow_clone(context.repo, workdir / "valkey-fuzzer", context.head_sha)

    # Build prompt.
    det_lines = []
    for a in anomalies[:15]:
        det_lines.append(f"- [{a.severity}] {a.title}: {a.evidence}")
    for n in normals[:10]:
        det_lines.append(f"- [normal] {n}")

    prompt = _CLAUDE_PROMPT_TEMPLATE.format(
        repo=context.repo, run_url=context.run_url,
        conclusion=context.conclusion,
        valkey_sha=context.tested_valkey_sha or "unknown",
        scenario_id=context.scenario_id or "unknown",
        seed=context.seed or "unknown",
        deterministic_summary="\n".join(det_lines) or "None.",
    )

    result = run_agent("fuzzer_analysis_readonly", prompt, cwd=str(workdir))
    if result.returncode != 0:
        raise RuntimeError(f"Claude Code failed (rc={result.returncode})")

    # Parse response (handles stream-json and plain JSON).
    text = ""
    for line in result.stdout.strip().splitlines():
        try:
            ev = json.loads(line)
            if ev.get("type") == "result" and "result" in ev:
                text = ev["result"]
        except (json.JSONDecodeError, TypeError):
            continue
    if not text:
        text = result.stdout.strip()

    # Extract JSON from possible markdown fences.
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]) if len(lines) >= 3 else text

    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("No JSON in Claude response")
    return json.loads(m.group(0))


def _shallow_clone(repo: str, dest: Path, sha: str | None) -> None:
    """Clone a repo shallowly, optionally checking out a specific commit."""
    args = ["git", "clone", "--filter=blob:none"]
    if not sha:
        args.extend(["--depth", "1"])
    args.extend([f"https://github.com/{repo}.git", str(dest)])

    r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        logger.warning("Clone %s failed: %s", repo, r.stderr[:100])
        return
    if sha:
        subprocess.run(["git", "fetch", "--depth", "1", "origin", sha],
                       cwd=str(dest), capture_output=True, timeout=30)
        subprocess.run(["git", "checkout", sha],
                       cwd=str(dest), capture_output=True, timeout=10)


# --- Main analyzer class ---

class FuzzerRunAnalyzer:
    """Analyzes fuzzer workflow runs: pattern matching + Claude Code."""

    def __init__(self, github_client: Any, *, github_token: str | None = None,
                 artifact_client: ArtifactClient | None = None) -> None:
        self._gh = github_client
        self._client = artifact_client or ArtifactClient(github_client, token=github_token)

    def analyze(self, repo: str, run_id: int, *, workflow_file: str) -> FuzzerRunAnalysis:
        gh_repo = self._gh.get_repo(repo)
        run = gh_repo.get_workflow_run(run_id)
        context = FuzzerRunContext(
            repo=repo, workflow_file=workflow_file, run_id=run_id,
            run_url=getattr(run, "html_url", ""),
            conclusion=str(getattr(run, "conclusion", "") or ""),
            head_sha=str(getattr(run, "head_sha", "") or ""),
        )

        # Fetch artifacts.
        artifacts = self._client.list_run_artifacts(repo, run_id)
        bundle = next((a for a in artifacts if a.name.startswith("fuzzer-run-artifacts") and not a.expired), None)
        if bundle:
            files = self._client.download_artifact(repo, bundle.artifact_id)
            _load_artifacts(context, files)

        # Fallback: download run logs if no structured data.
        if not context.results and not context.node_logs:
            log_files = self._client.download_run_logs(repo, run_id)
            parts = [payload.decode("utf-8", errors="replace")
                     for path, payload in sorted(log_files.items())
                     if path.endswith((".txt", ".log"))]
            if parts:
                context.raw_job_log = "\n".join(parts)

        # Extract metadata from job log if not in artifacts.
        if context.raw_job_log:
            cleaned = _clean_log(context.raw_job_log)
            if not context.scenario_id:
                m = re.search(r"Scenario:\s*(\S+)", cleaned)
                if m:
                    context.scenario_id = m.group(1)
            if not context.seed:
                m = re.search(r"Seed:\s*(\S+)", cleaned)
                if m:
                    context.seed = m.group(1)

        # Phase 1: deterministic pattern matching.
        anomalies, normals = _scan_logs(context)

        # Phase 2: Claude Code deep analysis.
        model_payload: dict[str, Any] = {}
        try:
            tmpdir = Path(tempfile.mkdtemp(prefix="fuzzer-"))
            try:
                model_payload = _invoke_claude(context, anomalies, normals, tmpdir)
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception as exc:
            logger.warning("Claude analysis failed for run %s: %s", run_id, exc)

        # Merge results.
        if isinstance(model_payload.get("anomalies"), list):
            for raw in model_payload["anomalies"]:
                if isinstance(raw, dict) and raw.get("title"):
                    anomalies.append(FuzzerSignal(
                        raw["title"], raw.get("severity", "warning"),
                        str(raw.get("evidence", "")),
                    ))
        if isinstance(model_payload.get("normal_signals"), list):
            normals.extend(s for s in model_payload["normal_signals"] if isinstance(s, str))

        overall_status, triage_verdict = _triage(anomalies)
        # Let Claude override if it found something stronger.
        if model_payload.get("overall_status") == "anomalous" and overall_status != "anomalous":
            overall_status = "anomalous"
        if model_payload.get("triage_verdict") in ("likely-core-valkey-bug",) and triage_verdict != "likely-core-valkey-bug":
            triage_verdict = "likely-core-valkey-bug"

        summary = str(model_payload.get("summary") or "")
        if not summary:
            if anomalies:
                summary = f"Run {run_id}: {len(anomalies)} anomalies detected ({anomalies[0].title})"
            else:
                summary = f"Run {run_id}: no anomalies detected"

        root_cause = model_payload.get("root_cause_category")
        fingerprint = compute_fingerprint(
            repo=repo, workflow_file=workflow_file,
            root_cause_category=root_cause if isinstance(root_cause, str) else None,
            anomalies=anomalies,
        )

        hint = model_payload.get("reproduction_hint")
        if not hint and context.seed:
            hint = f"valkey-fuzzer cluster --seed {context.seed}"

        labels = ["possible-valkey-bug"] if "bug" in triage_verdict else []

        return FuzzerRunAnalysis(
            repo=repo, workflow_file=workflow_file, run_id=run_id,
            run_url=context.run_url, conclusion=context.conclusion,
            head_sha=context.head_sha, overall_status=overall_status,
            triage_verdict=triage_verdict, summary=summary,
            anomalies=anomalies, normal_signals=normals,
            scenario_id=context.scenario_id, seed=context.seed,
            tested_valkey_sha=context.tested_valkey_sha,
            root_cause_category=root_cause if isinstance(root_cause, str) else None,
            reproduction_hint=hint if isinstance(hint, str) else None,
            incident_fingerprint=fingerprint, suggested_labels=labels,
        )
