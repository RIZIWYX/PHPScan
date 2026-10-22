"""Phase 4 - sortie SARIF 2.1.0 (lisible par GitHub Code Scanning)."""

from __future__ import annotations

import json

from .. import __version__
from ..models import Finding, Rule, Severity

LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}


def render(findings: list[Finding], rules: list[Rule]) -> str:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "phpscan",
                "version": __version__,
                "informationUri": "https://github.com/RIZIWYX/phpscan",
                "rules": [{
                    "id": r.id,
                    "name": r.name,
                    "shortDescription": {"text": r.message},
                    "help": {"text": r.fix},
                    "properties": {"tags": ["security", r.cwe]},
                } for r in rules],
            }},
            "results": [{
                "ruleId": f.rule_id,
                "level": LEVEL[f.severity],
                "message": {"text": f"{f.message}. {f.fix}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }}],
            } for f in findings],
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
