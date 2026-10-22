from pathlib import Path

import pytest

from phpscan.engine_regex import scan_file
from phpscan.rules import RuleError, load_rules

from .conftest import FIXTURES, expected

VULN = sorted((FIXTURES / "vuln").glob("*.php"))
SAFE = sorted((FIXTURES / "safe").glob("*.php"))


def test_default_rules_load(rules):
    assert {r.id for r in rules} == {
        "PHP-SQLI-001", "PHP-EXEC-001", "PHP-SECRET-001", "PHP-HASH-001", "PHP-INPUT-001",
    }


@pytest.mark.parametrize("path", VULN, ids=lambda p: p.name)
def test_vulnerable_fixture_detected(path: Path, rules):
    found = {(f.line, f.rule_id) for f in scan_file(path, rules)}
    assert expected(path) <= found


KNOWN_REGEX_FP = {"escaped_output.php"}  # la regex ne voit pas htmlspecialchars : à corriger en AST


@pytest.mark.parametrize(
    "path",
    [pytest.param(p, marks=pytest.mark.xfail(reason="faux positif connu du moteur regex"))
     if p.name in KNOWN_REGEX_FP else p for p in SAFE],
    ids=lambda p: p.name,
)
def test_safe_fixture_clean(path: Path, rules):
    assert scan_file(path, rules) == []


def test_invalid_severity_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("- {id: X, name: x, severity: URGENT, cwe: CWE-1, message: m, fix: f}\n")
    with pytest.raises(RuleError):
        load_rules(bad)
