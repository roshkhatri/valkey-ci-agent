"""Workflow artifact and log retrieval for fuzzer runs."""

from __future__ import annotations

import io
import logging
import zipfile
from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING, Any
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scripts.common.github_client import retry_github_call

if TYPE_CHECKING:
    from github import Github

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkflowArtifact:
    artifact_id: int
    name: str
    size_in_bytes: int
    expired: bool


class ArtifactClient:
    """Fetches workflow artifacts and logs from GitHub Actions."""

    def __init__(self, github_client: Github, *, token: str | None = None) -> None:
        self._gh = github_client
        self._token = token

    def list_recent_runs(
        self, repo_full_name: str, workflow_file: str,
        *, event: str = "schedule", max_runs: int = 6,
    ) -> list[Any]:
        repo = self._gh.get_repo(repo_full_name)
        workflow = repo.get_workflow(workflow_file)
        runs = workflow.get_runs(event=event, status="completed")
        return list(islice(runs, max_runs))

    def list_run_artifacts(self, repo_full_name: str, run_id: int) -> list[WorkflowArtifact]:
        repo = self._gh.get_repo(repo_full_name)

        def _fetch() -> object:
            _, data = repo._requester.requestJsonAndCheck(
                "GET", f"/repos/{repo_full_name}/actions/runs/{run_id}/artifacts",
            )
            return data

        payload = retry_github_call(_fetch, retries=3, description=f"list artifacts {run_id}")
        if not isinstance(payload, dict):
            return []
        return [
            WorkflowArtifact(
                artifact_id=a["id"], name=a["name"],
                size_in_bytes=a.get("size_in_bytes", 0),
                expired=a.get("expired", False),
            )
            for a in payload.get("artifacts", [])
            if isinstance(a, dict) and isinstance(a.get("id"), int)
        ]

    def download_artifact(self, repo_full_name: str, artifact_id: int) -> dict[str, bytes]:
        path = f"/repos/{repo_full_name}/actions/artifacts/{artifact_id}/zip"
        blob = self._download(path)
        return _extract_zip(blob)

    def download_run_logs(self, repo_full_name: str, run_id: int) -> dict[str, bytes]:
        path = f"/repos/{repo_full_name}/actions/runs/{run_id}/logs"
        blob = self._download(path)
        return _extract_zip(blob)

    def _download(self, path: str) -> bytes:
        if not self._token:
            return b""
        req = Request(
            f"https://api.github.com{path}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "valkey-ci-agent",
            },
        )
        opener = build_opener(_StripAuthRedirect())
        with opener.open(req, timeout=120) as resp:
            return resp.read()


class _StripAuthRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None and new_req.host != req.host:
            new_req.remove_header("Authorization")
        return new_req


def _extract_zip(blob: bytes) -> dict[str, bytes]:
    if not blob:
        return {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return {m.filename: zf.read(m) for m in zf.infolist() if not m.is_dir()}
    except (zipfile.BadZipFile, Exception):
        return {}
