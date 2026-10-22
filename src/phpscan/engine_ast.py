"""Phase 6 - moteur AST (tree-sitter) avec suivi de données souillées.

Plan d'implémentation :
1. Parser le fichier avec tree-sitter-php et afficher l'arbre pour repérer les nœuds utiles :
   function_call_expression, assignment_expression, binary_expression,
   subscript_expression, encapsed_string.
2. Règles structurelles : un vrai appel à eval/exec (pas un mot dans une chaîne).
3. Taint tracking intraprocédural :
   - SOURCES : $_GET, $_POST, $_REQUEST, $_COOKIE
   - SANITIZERS : intval, htmlspecialchars, filter_input, (int)...
   - SINKS : mysqli_query, ->query, eval, system, echo, include...
   - parcourir les instructions dans l'ordre, maintenir l'ensemble des variables souillées,
     alerter quand une variable souillée atteint un sink.
"""

from __future__ import annotations

from pathlib import Path

from .models import Finding, Rule

SOURCES = {"_GET", "_POST", "_REQUEST", "_COOKIE"}
SANITIZERS = {"intval", "floatval", "htmlspecialchars", "htmlentities", "filter_input",
              "filter_var", "escapeshellarg", "addslashes"}
SINKS = {"mysqli_query", "mysql_query", "pg_query", "query", "exec", "eval", "system",
         "shell_exec", "passthru", "echo", "print", "include", "require"}


def _parser():
    try:
        import tree_sitter_php
        from tree_sitter import Language, Parser
    except ImportError as e:  # pragma: no cover
        raise SystemExit("Moteur AST indisponible : pip install -e '.[ast]'") from e
    return Parser(Language(tree_sitter_php.language_php()))


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    _parser()
    raise NotImplementedError("TODO phase 6 : moteur AST")
