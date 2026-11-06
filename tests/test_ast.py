"""Tests du moteur AST (phase 6).

tests/fixtures : jeu de développement, utilisé pour écrire le moteur -> tout doit passer.
tests/holdout  : jeu de validation, écrit APRÈS le moteur et jamais utilisé pour le régler.
Ses échecs sont des limites réelles, documentées en xfail strict.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_php")

from phpscan.engine_ast import scan_file, scan_source  # noqa: E402

from .conftest import expected  # noqa: E402

ROOT = Path(__file__).parent
DEV_VULN = sorted((ROOT / "fixtures" / "vuln").glob("*.php"))
DEV_SAFE = sorted((ROOT / "fixtures" / "safe").glob("*.php"))
HOLD_VULN = sorted((ROOT / "holdout" / "vuln").glob("*.php"))
HOLD_SAFE = sorted((ROOT / "holdout" / "safe").glob("*.php"))

KNOWN_AST_FN = {
    "function_param.php": "analyse intraprocédurale : la souillure ne traverse pas les appels",
    "request_array.php": "copie d'un tableau source ($data = $_REQUEST) non suivie",
    "config_secret.php": "constantes de classe (const X = ...) non analysées",
}


def _hold(paths):
    return [pytest.param(p, marks=pytest.mark.xfail(reason=KNOWN_AST_FN[p.name], strict=True))
            if p.name in KNOWN_AST_FN else p for p in paths]


@pytest.mark.parametrize("path", DEV_VULN + _hold(HOLD_VULN), ids=lambda p: p.name)
def test_ast_detects(path: Path, rules):
    found = {(f.line, f.rule_id) for f in scan_file(path, rules)}
    assert expected(path) <= found


@pytest.mark.parametrize("path", DEV_SAFE + HOLD_SAFE, ids=lambda p: p.name)
def test_ast_no_false_positive(path: Path, rules):
    assert scan_file(path, rules) == []


@pytest.mark.parametrize("code", [
    "<?php\n// eval($_GET['x']);\n",
    "<?php\n$s = \"system('ls')\";\n",
    "<?php\necho htmlspecialchars($_GET['a']);\n",
    "<?php\n$x = intval($_GET['id']);\nmysqli_query($db, \"SELECT * FROM t WHERE id=\" . $x);\n",
])
def test_ast_ignores_safe_snippets(code, rules):
    assert scan_source(code, "t.php", rules) == []


def test_taint_propagates_through_variables(rules):
    code = "<?php\n$a = $_GET['a'];\n$b = 'x' . $a;\n$c = $b;\necho $c;\n"
    assert [(f.line, f.rule_id) for f in scan_source(code, "t.php", rules)] == [
        (5, "PHP-INPUT-001")]


def test_reassignment_cleans_variable(rules):
    code = "<?php\n$a = $_GET['a'];\n$a = 'constante';\necho $a;\n"
    assert scan_source(code, "t.php", rules) == []


def test_ignore_marker(rules):
    code = "<?php\necho $_GET['a']; // phpscan-ignore\n"
    assert scan_source(code, "t.php", rules) == []


def test_ternary_condition_does_not_taint_result(rules):
    """Bug trouvé sur Yapply (accueil.php) : la condition ne souille pas le résultat."""
    code = ("<?php\n$id = isset($_POST['id']) && $_POST['id'] !== '' ? (int) $_POST['id'] : null;\n"
            "echo $id;\n")
    assert scan_source(code, "t.php", rules) == []


def test_ternary_tainted_branch_is_tainted(rules):
    code = "<?php\n$x = isset($_GET['a']) ? $_GET['a'] : 'defaut';\necho $x;\n"
    assert [f.rule_id for f in scan_source(code, "t.php", rules)] == ["PHP-INPUT-001"]
