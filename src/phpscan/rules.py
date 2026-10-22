"""Phase 2 - chargement et validation des règles YAML."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Rule, Severity

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "default.yml"
REQUIRED = {"id", "name", "severity", "cwe", "message", "fix"}


class RuleError(ValueError):
    pass


def load_rules(path: str | Path = DEFAULT_RULES) -> list[Rule]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    rules: list[Rule] = []
    for i, raw in enumerate(data):
        missing = REQUIRED - raw.keys()
        if missing:
            raise RuleError(f"Règle n°{i}: champs manquants {sorted(missing)}")
        try:
            severity = Severity[raw["severity"].upper()]
        except KeyError as e:
            raise RuleError(f"{raw['id']}: sévérité inconnue {raw['severity']!r}") from e
        pattern = raw.get("pattern", "")
        try:
            regex = re.compile(pattern) if pattern else None
        except re.error as e:
            raise RuleError(f"{raw['id']}: regex invalide ({e})") from e
        rules.append(
            Rule(
                id=raw["id"], name=raw["name"], severity=severity, cwe=raw["cwe"],
                message=raw["message"], fix=raw["fix"], pattern=pattern, regex=regex,
            )
        )
    return rules
