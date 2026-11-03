from pathlib import Path

import pytest

from phpscan.engine_regex import scan_file
from phpscan.metrics import expected
from phpscan.rules import RuleError, load_rules

from .conftest import FIXTURES

VULN = sorted((FIXTURES / "vuln").glob("*.php"))
SAFE = sorted((FIXTURES / "safe").glob("*.php"))

# Limites connues du moteur regex, mesurées par phpscan-metrics.
# strict=True : si une amélioration corrige un cas, le test échoue pour qu'on retire
# le fichier de la liste. Objectif de la phase 6 (AST) : vider ces deux ensembles.
KNOWN_REGEX_FN = {
    "exec_backticks.php", "hash_hash_fn.php", "hash_md5_post.php", "hash_md5_salt.php",
    "input_short_echo.php", "input_var_then_echo.php", "secret_array.php",
    "secret_define.php", "secret_pdo.php", "sqli_interpolated.php", "sqli_multiline.php",
    "sqli_pdo_query.php",
}
KNOWN_REGEX_FP = {
    "escaped_output.php", "exec_word_in_string.php", "input_cast.php", "input_htmlentities.php",
    "secret_form_field.php", "secret_label.php", "secret_placeholder.php", "sqli_in_string.php",
    "sqli_intval.php",
}


def _params(paths, known, reason):
    return [pytest.param(p, marks=pytest.mark.xfail(reason=reason, strict=True))
            if p.name in known else p for p in paths]


def test_default_rules_load(rules):
    assert {r.id for r in rules} == {
        "PHP-SQLI-001", "PHP-EXEC-001", "PHP-SECRET-001", "PHP-HASH-001", "PHP-INPUT-001",
    }


@pytest.mark.parametrize("path", _params(VULN, KNOWN_REGEX_FN, "faux négatif connu (regex)"),
                         ids=lambda p: p.name)
def test_vulnerable_fixture_detected(path: Path, rules):
    found = {(f.line, f.rule_id) for f in scan_file(path, rules)}
    assert expected(path) <= found


@pytest.mark.parametrize("path", _params(SAFE, KNOWN_REGEX_FP, "faux positif connu (regex)"),
                         ids=lambda p: p.name)
def test_safe_fixture_clean(path: Path, rules):
    assert scan_file(path, rules) == []


def test_every_vuln_fixture_has_expectation():
    for p in VULN:
        assert expected(p), f"{p.name} n'a aucun marqueur EXPECT"


def test_invalid_severity_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("- {id: X, name: x, severity: URGENT, cwe: CWE-1, message: m, fix: f}\n")
    with pytest.raises(RuleError):
        load_rules(bad)
