"""Phase 4 - affichage console avec rich."""

from __future__ import annotations

from collections import Counter, defaultdict

from rich.console import Console

from ..models import Finding, Severity

COLORS = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan"}


def render(findings: list[Finding], files_scanned: int) -> None:
    console = Console()
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)
    for file, items in sorted(by_file.items()):
        console.rule(f"[bold]{file}")
        for f in items:
            color = COLORS[f.severity]
            console.print(f"[{color}]{f.severity.name:<6}[/] {f.file}:{f.line}  "
                          f"[bold]{f.rule_id}[/] {f.message}")
            console.print(f"       [dim]{f.snippet}[/]")
            console.print(f"       -> {f.fix}")
    counts = Counter(f.severity.name for f in findings)
    console.rule()
    console.print(f"{files_scanned} fichier(s) analysé(s), {len(findings)} alerte(s) : "
                  + ", ".join(f"{n} {s}" for s, n in counts.most_common()) if findings
                  else f"{files_scanned} fichier(s) analysé(s), aucune alerte.")
