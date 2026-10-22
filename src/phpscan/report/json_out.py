"""Phase 4 - sortie JSON."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .. import __version__
from ..models import Finding


def render(findings: list[Finding], files_scanned: int, duration_s: float, engine: str) -> str:
    return json.dumps(
        {
            "tool": "phpscan",
            "version": __version__,
            "engine": engine,
            "date": datetime.now(UTC).isoformat(),
            "files_scanned": files_scanned,
            "duration_s": round(duration_s, 3),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
        ensure_ascii=False,
    )
