"""Phase 1 - découverte et lecture des fichiers PHP."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

PHP_EXTENSIONS = {".php", ".phtml", ".inc"}
DEFAULT_EXCLUDES = {"vendor", "node_modules", ".git"}
MAX_SIZE = 2 * 1024 * 1024  # 2 Mo


def discover(paths: Iterable[str | Path], exclude: Iterable[str] = ()) -> Iterator[Path]:
    """Renvoie les fichiers PHP trouvés sous `paths`, en ignorant les dossiers exclus."""
    excluded = DEFAULT_EXCLUDES | set(exclude)
    for root in map(Path, paths):
        candidates = [root] if root.is_file() else root.rglob("*")
        for p in candidates:
            if not p.is_file() or p.suffix.lower() not in PHP_EXTENSIONS:
                continue
            if any(part in excluded for part in p.parts):
                continue
            if p.stat().st_size > MAX_SIZE:
                continue
            yield p


def read_source(path: Path) -> str:
    """Lit un fichier sans jamais planter sur un encodage invalide."""
    return path.read_text(encoding="utf-8", errors="replace")
