"""Phase 3 - moteur de détection par expressions régulières."""

from __future__ import annotations

from pathlib import Path

from .models import Finding, Rule
from .preprocess import line_of, strip_comments

IGNORE_MARK = "phpscan-ignore"


def scan_source(code: str, filename: str, rules: list[Rule]) -> list[Finding]:
    clean = strip_comments(code)
    lines = code.splitlines()
    findings: dict[tuple[str, int], Finding] = {}
    for rule in rules:
        if rule.regex is None:
            continue
        for m in rule.regex.finditer(clean):
            line = line_of(clean, m.start())
            original = lines[line - 1] if line <= len(lines) else ""
            if IGNORE_MARK in original:
                continue
            col = m.start() - (clean.rfind("\n", 0, m.start()) + 1) + 1
            findings.setdefault(
                (rule.id, line),
                Finding(
                    file=filename, line=line, column=col, rule_id=rule.id,
                    severity=rule.severity, message=rule.message, fix=rule.fix,
                    snippet=original.strip(),
                ),
            )
    return sorted(findings.values(), key=lambda f: (f.line, f.rule_id))


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    from .loader import read_source

    return scan_source(read_source(path), str(path), rules)
