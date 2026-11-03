"""Phase 6 - moteur AST (tree-sitter) avec suivi de données souillées (taint tracking).

Principe
--------
Le fichier PHP est transformé en arbre syntaxique par tree-sitter, puis parcouru dans
l'ordre du programme. On maintient deux ensembles de variables :

- ``tainted`` : variables dont la valeur vient de l'utilisateur (source : $_GET, $_POST...)
- ``clean``   : variables dont la valeur est sûre (littéral, ou passée par un sanitizer)

Une alerte est levée quand une valeur souillée atteint un *sink* (echo, requête SQL,
include...) sans être passée par un *sanitizer* (htmlspecialchars, intval, cast (int)...).

Limites assumées : analyse intraprocédurale (chaque fonction est analysée seule, ses
paramètres sont considérés comme inconnus), pas de suivi entre fichiers, pas de suivi
des propriétés d'objets ni des cases de tableaux.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Rule

SOURCES = {"_GET", "_POST", "_REQUEST", "_COOKIE"}
SANITIZERS = {
    "intval", "floatval", "boolval", "htmlspecialchars", "htmlentities", "strip_tags",
    "filter_input", "filter_var", "escapeshellarg", "escapeshellcmd", "addslashes",
    "mysqli_real_escape_string", "urlencode", "rawurlencode", "basename", "md5", "sha1",
    "hash", "password_hash", "count", "strlen", "json_encode",
}
SAFE_CASTS = {"int", "integer", "float", "double", "bool", "boolean"}
WHITELIST_CHECKS = {"in_array", "array_key_exists", "ctype_digit", "ctype_alnum", "is_numeric"}

SQL_FUNCS = {"mysqli_query", "mysql_query", "pg_query", "sqlite_query", "mysqli_multi_query"}
SQL_METHODS = {"query", "exec", "multi_query"}
EXEC_FUNCS = {"eval", "exec", "system", "shell_exec", "passthru", "popen", "proc_open", "assert"}
WEAK_HASH = {"md5", "sha1"}

SECRET_NAME = re.compile(r"pass(word)?|pwd|mdp|secret|api_?key|token", re.IGNORECASE)
PASSWORD_NAME = re.compile(r"pass|pwd|mdp", re.IGNORECASE)
IGNORE_MARK = "phpscan-ignore"


def _parser():
    try:
        import tree_sitter_php
        from tree_sitter import Language, Parser
    except ImportError as e:  # pragma: no cover
        raise SystemExit("Moteur AST indisponible : pip install -e '.[ast]'") from e
    return Parser(Language(tree_sitter_php.language_php()))


_PARSER = None


@dataclass
class State:
    tainted: set[str] = field(default_factory=set)
    clean: set[str] = field(default_factory=set)


class Analyzer:
    def __init__(self, code: bytes, filename: str, rules: list[Rule]):
        self.code = code
        self.lines = code.decode("utf-8", errors="replace").splitlines()
        self.filename = filename
        self.rules = {r.id: r for r in rules}
        self.found: dict[tuple[str, int], Finding] = {}

    # ---------- utilitaires ----------
    def text(self, node) -> str:
        return self.code[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def name_of(self, node) -> str:
        """Nom d'une variable, d'une fonction ou d'une méthode."""
        n = node.child_by_field_name("name")
        if n is None:
            n = next((c for c in node.named_children if c.type == "name"), None)
        return self.text(n) if n is not None else ""

    def args(self, node) -> list:
        a = node.child_by_field_name("arguments")
        if a is None:
            a = next((c for c in node.named_children if c.type == "arguments"), None)
        if a is None:
            return []
        # seuls les nœuds « argument » comptent : un commentaire peut se glisser entre eux
        return [c.named_children[0] for c in a.named_children
                if c.type == "argument" and c.named_children]

    def string_value(self, node) -> str | None:
        """Valeur d'une chaîne littérale (sans variable interpolée), sinon None."""
        if node.type not in ("string", "encapsed_string"):
            return None
        if any(c.type not in ("string_content", "escape_sequence") for c in node.named_children):
            return None
        return "".join(self.text(c) for c in node.named_children)

    def report(self, rule_id: str, node) -> None:
        rule = self.rules.get(rule_id)
        if rule is None:
            return
        line = node.start_point[0] + 1
        original = self.lines[line - 1] if line <= len(self.lines) else ""
        if IGNORE_MARK in original:
            return
        self.found.setdefault((rule_id, line), Finding(
            file=self.filename, line=line, column=node.start_point[1] + 1, rule_id=rule_id,
            severity=rule.severity, message=rule.message, fix=rule.fix,
            snippet=original.strip(), engine="ast",
        ))

    # ---------- suivi de souillure ----------
    def is_tainted(self, node, st: State) -> bool:
        t = node.type
        if t == "subscript_expression":
            base = node.named_children[0] if node.named_children else None
            if base is not None and base.type == "variable_name" and self.name_of(base) in SOURCES:
                return True
        if t == "variable_name":
            return self.name_of(node) in st.tainted
        if t == "function_call_expression" and self.name_of(node).lower() in SANITIZERS:
            return False
        if t == "cast_expression":
            cast = next((c for c in node.named_children if c.type == "cast_type"), None)
            if cast is not None and self.text(cast).lower() in SAFE_CASTS:
                return False
        if t == "conditional_expression":
            cond = node.named_children[0] if node.named_children else None
            if cond is not None and cond.type == "function_call_expression" \
                    and self.name_of(cond).lower() in WHITELIST_CHECKS:
                return False  # valeur filtrée par liste blanche
        if t in ("isset_expression", "unset_statement"):
            return False
        return any(self.is_tainted(c, st) for c in node.named_children)

    def is_unknown_dynamic(self, node, st: State) -> bool:
        """Pour le SQL : une variable ni souillée ni connue comme sûre, insérée dans la requête."""
        if node.type == "variable_name":
            return self.name_of(node) not in st.clean
        if node.type == "function_call_expression" and self.name_of(node).lower() in SANITIZERS:
            return False
        if node.type == "cast_expression":
            return False
        return any(self.is_unknown_dynamic(c, st) for c in node.named_children)

    def first_line_node(self, node, st: State):
        """Le sous-nœud souillé le plus précis, pour rapporter la bonne ligne."""
        for c in node.named_children:
            if self.is_tainted(c, st) or self.is_unknown_dynamic(c, st):
                return self.first_line_node(c, st) if c.type in ("arguments", "argument") else c
        return node

    # ---------- parcours ----------
    def run(self, root) -> list[Finding]:
        self.visit(root, State())
        return sorted(self.found.values(), key=lambda f: (f.line, f.rule_id))

    def visit(self, node, st: State) -> None:
        t = node.type
        if t in ("function_definition", "method_declaration", "anonymous_function",
                 "arrow_function"):
            body_state = State()
            for c in node.named_children:
                self.visit(c, body_state)
            return

        if t == "php_tag" and self.text(node) == "<?=":
            nxt = node.next_named_sibling
            if nxt is not None and self.is_tainted(nxt, st):
                self.report("PHP-INPUT-001", nxt)

        # Les enfants d'abord pour les affectations (la droite est évaluée avant la gauche)
        if t in ("assignment_expression", "augmented_assignment_expression"):
            left, right = node.named_children[0], node.named_children[-1]
            self.visit(right, st)
            self.check_secret_assignment(left, right)
            if left.type == "variable_name":
                name = self.name_of(left)
                tainted = self.is_tainted(right, st) or (
                    t == "augmented_assignment_expression" and name in st.tainted)
                if tainted:
                    st.tainted.add(name)
                    st.clean.discard(name)
                else:
                    st.tainted.discard(name)
                    if not self.is_unknown_dynamic(right, st):
                        st.clean.add(name)
                    else:
                        st.clean.discard(name)
            return

        self.check_node(node, st)
        for c in node.named_children:
            self.visit(c, st)

    # ---------- règles ----------
    def check_node(self, node, st: State) -> None:
        t = node.type
        if t == "function_call_expression":
            fname = self.name_of(node).lower()
            args = self.args(node)
            if fname in EXEC_FUNCS:
                self.report("PHP-EXEC-001", node)
            if fname in SQL_FUNCS and args:
                query = args[-1] if fname != "pg_query" or len(args) > 1 else args[0]
                self.check_sql(query, st)
            if fname in WEAK_HASH and args and self.mentions_password(args[0]):
                self.report("PHP-HASH-001", node)
            if fname == "hash" and len(args) >= 2:
                algo = self.string_value(args[0])
                if algo and algo.lower() in WEAK_HASH and self.mentions_password(args[1]):
                    self.report("PHP-HASH-001", node)
            if fname == "define" and len(args) >= 2:
                const = self.string_value(args[0])
                if const and SECRET_NAME.search(const) and self.looks_like_secret(args[1]):
                    self.report("PHP-SECRET-001", node)
        elif t == "member_call_expression":
            if self.name_of(node).lower() in SQL_METHODS:
                args = self.args(node)
                if args:
                    self.check_sql(args[0], st)
        elif t == "shell_command_expression":
            self.report("PHP-EXEC-001", node)
        elif t == "object_creation_expression" and self.name_of(node) == "PDO":
            args = self.args(node)
            if len(args) >= 3 and self.looks_like_secret(args[2]):
                self.report("PHP-SECRET-001", args[2])
        elif t == "array_element_initializer" and len(node.named_children) == 2:
            key, val = node.named_children
            k = self.string_value(key)
            if k and SECRET_NAME.search(k) and self.looks_like_secret(val):
                self.report("PHP-SECRET-001", node)
        elif t in ("echo_statement", "print_intrinsic", "include_expression",
                   "include_once_expression", "require_expression", "require_once_expression"):
            for c in node.named_children:
                if self.is_tainted(c, st):
                    self.report("PHP-INPUT-001", node)
                    break

    def check_sql(self, query, st: State) -> None:
        if self.string_value(query) is not None:
            return  # requête constante
        if self.is_tainted(query, st) or (
            query.type in ("binary_expression", "encapsed_string")
            and self.is_unknown_dynamic(query, st)
        ):
            self.report("PHP-SQLI-001", self.first_line_node(query, st)
                        if query.type != "variable_name" else query)

    def check_secret_assignment(self, left, right) -> None:
        if left.type == "variable_name" and SECRET_NAME.search(self.name_of(left)) \
                and self.looks_like_secret(right):
            self.report("PHP-SECRET-001", left)

    def looks_like_secret(self, node) -> bool:
        """Chaîne littérale d'au moins 6 caractères, sans espace, avec lettres ET chiffres.
        Écarte "", "CHANGEME", "password", "Votre mot de passe"..."""
        v = self.string_value(node)
        return bool(v and len(v) >= 6 and not re.search(r"\s", v)
                    and re.search(r"\d", v) and re.search(r"[A-Za-z]", v))

    def mentions_password(self, node) -> bool:
        """L'argument fait-il référence à un mot de passe (nom de variable ou clé) ?"""
        if node.type == "variable_name":
            return bool(PASSWORD_NAME.search(self.name_of(node)))
        if node.type == "string" and node.parent is not None \
                and node.parent.type == "subscript_expression":
            return bool(PASSWORD_NAME.search(self.text(node)))
        return any(self.mentions_password(c) for c in node.named_children)


def scan_source(code: str, filename: str, rules: list[Rule]) -> list[Finding]:
    global _PARSER
    if _PARSER is None:
        _PARSER = _parser()
    data = code.encode("utf-8")
    tree = _PARSER.parse(data)
    return Analyzer(data, filename, rules).run(tree.root_node)


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    from .loader import read_source

    return scan_source(read_source(path), str(path), rules)
