"""Stable fingerprints for fuzzer incident deduplication."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

from scripts.fuzzer.models import FuzzerSignal

_VOLATILE_RE = re.compile(
    r"0x[0-9a-f]+|\b[0-9a-f]{7,40}\b|\bnode[-_ ]?\d+\b|\b\d+\b",
    re.IGNORECASE,
)


def compute_fingerprint(
    *,
    repo: str,
    workflow_file: str,
    root_cause_category: str | None,
    anomalies: Iterable[FuzzerSignal],
) -> str:
    """Stable hash grouping repeated failures by shape, not run ID."""
    parts = [repo.lower(), workflow_file.lower(), (root_cause_category or "").lower()]
    shapes = sorted({f"{s.title}:{s.evidence}" for s in anomalies})[:8]
    for shape in shapes:
        parts.append(_VOLATILE_RE.sub("_", shape.lower()))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]
