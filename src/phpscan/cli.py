"""Point d'entrée en ligne de commande."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .loader import discover
from .models import Finding, Severity
from .rules import DEFAULT_RULES, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phpscan",
        description="Analyseur statique pédagogique de motifs à risque dans du code PHP.",
    )
    p.add_argument("paths", nargs="+", help="Fichiers ou dossiers à analyser")
    p.add_argument("--engine", choices=["regex", "ast", "llm"], default="regex")
    p.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    p.add_argument("-o", "--output", help="Fichier de sortie (json/sarif)")
    p.add_argument("--rules", default=str(DEFAULT_RULES), help="Fichier de règles YAML")
    p.add_argument("--min-severity", choices=[s.name for s in Severity], default="LOW")
    p.add_argument("--exclude", default="", help="Dossiers à ignorer, séparés par des virgules")
    p.add_argument("--version", action="version", version=f"phpscan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules = load_rules(args.rules)
    threshold = Severity[args.min_severity]

    if args.engine == "regex":
        from .engine_regex import scan_file
    elif args.engine == "ast":
        from .engine_ast import scan_file
    else:
        from .engine_llm import scan_file

    excludes = [e for e in args.exclude.split(",") if e]
    files = list(discover(args.paths, excludes))
    start = time.perf_counter()
    findings: list[Finding] = []
    for path in files:
        findings.extend(f for f in scan_file(path, rules) if f.severity >= threshold)
    duration = time.perf_counter() - start

    if args.format == "console":
        from .report.console import render
        render(findings, len(files))
    else:
        if args.format == "json":
            from .report.json_out import render as render_json
            out = render_json(findings, len(files), duration, args.engine)
        else:
            from .report.sarif import render as render_sarif
            out = render_sarif(findings, rules)
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
        else:
            print(out)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
