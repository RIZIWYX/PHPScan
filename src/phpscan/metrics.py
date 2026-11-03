"""Phase 5 - précision et rappel par règle sur un jeu de fichiers étiquetés.

Chaque vulnérabilité attendue est marquée sur sa ligne par `EXPECT: <ID-de-règle>`.
Une alerte est un vrai positif (VP) si la même règle est attendue sur la même ligne,
sinon un faux positif (FP). Une vulnérabilité attendue sans alerte est un faux négatif (FN).

Usage : phpscan-metrics [dossier] [--engine regex|ast|llm] [--format table|json|markdown]
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .loader import discover
from .rules import DEFAULT_RULES, load_rules

EXPECT = re.compile(r"EXPECT:\s*([A-Z0-9\-]+)")
DEFAULT_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def expected(path: Path) -> set[tuple[int, str]]:
    """Ensemble des (ligne, règle) attendues dans un fichier."""
    out: set[tuple[int, str]] = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        out.update((i, rid) for rid in EXPECT.findall(line))
    return out


@dataclass
class Score:
    vp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.vp / (self.vp + self.fp) if self.vp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.vp / (self.vp + self.fn) if self.vp + self.fn else None


@dataclass
class Report:
    engine: str
    files: int
    duration_s: float
    per_rule: dict[str, Score] = field(default_factory=dict)
    misses: list[str] = field(default_factory=list)  # "FN fichier:ligne règle" / "FP ..."

    @property
    def total(self) -> Score:
        t = Score()
        for s in self.per_rule.values():
            t.vp, t.fp, t.fn = t.vp + s.vp, t.fp + s.fp, t.fn + s.fn
        return t


def evaluate(root: Path = DEFAULT_DIR, engine: str = "regex",
             rules_path: str | Path = DEFAULT_RULES) -> Report:
    rules = load_rules(rules_path)
    scan_file = importlib.import_module(f"phpscan.engine_{engine}").scan_file
    files = sorted(discover([root]))
    per_rule: dict[str, Score] = defaultdict(Score)
    for r in rules:
        per_rule[r.id]  # toutes les règles apparaissent, même à 0
    misses: list[str] = []
    start = time.perf_counter()
    for path in files:
        want = expected(path)
        got = {(f.line, f.rule_id) for f in scan_file(path, rules)}
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        for _line, rid in got & want:
            per_rule[rid].vp += 1
        for line, rid in sorted(got - want):
            per_rule[rid].fp += 1
            misses.append(f"FP {rel}:{line} {rid}")
        for line, rid in sorted(want - got):
            per_rule[rid].fn += 1
            misses.append(f"FN {rel}:{line} {rid}")
    return Report(engine, len(files), time.perf_counter() - start, dict(per_rule), misses)


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.0%}"


def to_markdown(rep: Report) -> str:
    lines = [f"Moteur `{rep.engine}` - {rep.files} fichiers - "
             f"{rep.duration_s / max(rep.files, 1) * 1000:.2f} ms/fichier", "",
             "| Règle | VP | FP | FN | Précision | Rappel |",
             "| --- | --- | --- | --- | --- | --- |"]
    for rid, s in sorted(rep.per_rule.items()):
        lines.append(f"| {rid} | {s.vp} | {s.fp} | {s.fn} | "
                     f"{_pct(s.precision)} | {_pct(s.recall)} |")
    t = rep.total
    lines.append(f"| **Total** | {t.vp} | {t.fp} | {t.fn} | "
                 f"**{_pct(t.precision)}** | **{_pct(t.recall)}** |")
    return "\n".join(lines)


def to_json(rep: Report) -> str:
    def score(s: Score) -> dict:
        return {**asdict(s), "precision": s.precision, "recall": s.recall}

    return json.dumps({
        "engine": rep.engine, "files": rep.files, "duration_s": round(rep.duration_s, 4),
        "per_rule": {k: score(v) for k, v in sorted(rep.per_rule.items())},
        "total": score(rep.total), "misses": rep.misses,
    }, indent=2, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phpscan-metrics", description=__doc__.splitlines()[0])
    p.add_argument("root", nargs="?", default=str(DEFAULT_DIR))
    p.add_argument("--engine", choices=["regex", "ast", "llm"], default="regex")
    p.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    args = p.parse_args(argv)
    try:
        rep = evaluate(Path(args.root), args.engine)
    except NotImplementedError as e:
        print(f"Moteur {args.engine} pas encore disponible : {e}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(to_json(rep))
    else:
        print(to_markdown(rep))
        if args.format == "table" and rep.misses:
            print("\nErreurs :")
            print("\n".join(f"  {m}" for m in rep.misses))
    return 0


if __name__ == "__main__":
    sys.exit(main())
