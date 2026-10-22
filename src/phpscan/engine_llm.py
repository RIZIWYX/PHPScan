"""Phase 7 bis - moteur LLM pour comparaison.

Protocole : prompt versionné (prompts/v1.txt), température 0, 3 lancements par fichier,
cache des réponses dans .cache/llm/ pour ne pas repayer, clé lue dans ANTHROPIC_API_KEY.
Ne jamais écrire de clé dans le code.
"""

from __future__ import annotations

from pathlib import Path

from .models import Finding, Rule

PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "v1.txt"
CACHE_DIR = Path(".cache/llm")


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    raise NotImplementedError("TODO phase 7 bis : moteur LLM")
