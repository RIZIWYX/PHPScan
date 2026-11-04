import json

from phpscan.metrics import Score, evaluate, to_json


def test_score_formulas():
    s = Score(vp=3, fp=1, fn=2)
    assert s.precision == 0.75
    assert s.recall == 0.6
    assert Score().precision is None


def test_evaluate_counts_vp_fp_fn(tmp_path):
    (tmp_path / "a.php").write_text("<?php\neval($x); // EXPECT: PHP-EXEC-001\n")
    (tmp_path / "b.php").write_text("<?php\n$h = md5($password);\n")  # FP volontaire
    (tmp_path / "c.php").write_text("<?php\n$y = 1; // EXPECT: PHP-SQLI-001\n")  # FN
    rep = evaluate(tmp_path)
    assert (rep.per_rule["PHP-EXEC-001"].vp, rep.total.fp, rep.total.fn) == (1, 1, 1)
    assert json.loads(to_json(rep))["total"]["vp"] == 1


def test_regex_baseline_does_not_regress():
    """Garde-fou : une modification des règles ne doit pas dégrader la référence mesurée."""
    total = evaluate().total
    assert total.precision >= 0.66
    assert total.recall >= 0.60
