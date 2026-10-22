"""Modèles de données partagés : règles et résultats."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    cwe: str
    message: str
    fix: str
    pattern: str = ""
    regex: re.Pattern[str] | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    column: int
    rule_id: str
    severity: Severity
    message: str
    fix: str
    snippet: str
    engine: str = "regex"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "message": self.message,
            "fix": self.fix,
            "snippet": self.snippet,
            "engine": self.engine,
        }
