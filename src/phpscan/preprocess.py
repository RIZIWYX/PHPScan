"""Suppression des commentaires PHP en conservant la position de chaque caractère."""

from __future__ import annotations

import re

# TODO phase 3 : gérer les chaînes contenant // ou # (ex: "http://...").
_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*|#[^\n]*", re.DOTALL)


def strip_comments(code: str) -> str:
    """Remplace les commentaires par des espaces de même longueur (sauts de ligne gardés)."""
    return _COMMENTS.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), code)


def line_of(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1
