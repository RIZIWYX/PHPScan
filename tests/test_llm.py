"""Tests du moteur LLM sans réseau : un faux client remplace l'API."""

import json

import pytest

from phpscan import engine_llm as llm
from phpscan.metrics import evaluate, main, stability


class FakeClient:
    model = "claude-haiku-5-5"

    def __init__(self, answers):
        self.answers = list(answers)   # textes renvoyés dans l'ordre (ou exceptions)
        self.prompts: list[str] = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return llm.Completion(answer, input_tokens=100, output_tokens=20)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(llm, "USAGE", llm.Usage())
    monkeypatch.delenv("PHPSCAN_LLM_RUN", raising=False)
    monkeypatch.delenv("PHPSCAN_LLM_CACHE", raising=False)
    yield
    llm.set_client(None)


CODE = "<?php\n$id = $_GET['id'];\nmysqli_query($db, 'SELECT ' . $id);\n"


def answer(*items):
    return json.dumps({"findings": list(items)})


def test_valid_answer_becomes_findings(rules):
    llm.set_client(FakeClient([answer({"line": 3, "rule_id": "PHP-SQLI-001",
                                       "explanation": "concaténation"})]))
    [f] = llm.scan_source(CODE, "a.php", rules)
    assert (f.line, f.rule_id, f.engine, f.severity.name) == (3, "PHP-SQLI-001", "llm", "HIGH")


def test_prompt_has_numbered_lines_and_braces_survive(rules):
    client = FakeClient([answer()])
    llm.set_client(client)
    llm.scan_source("<?php\nfunction f() { return 1; }\n", "b.php", rules)
    assert "   2 | function f() { return 1; }" in client.prompts[0]
    assert "{filename}" not in client.prompts[0] and "b.php" in client.prompts[0]


def test_markdown_wrapped_json_is_accepted(rules):
    llm.set_client(FakeClient(["```json\n" + answer({"line": 2, "rule_id": "PHP-INPUT-001"})
                               + "\n```"]))
    assert [f.line for f in llm.scan_source(CODE, "c.php", rules)] == [2]


@pytest.mark.parametrize("bad", ["pas de json", '{"autre": 1}', '{"findings": "non"}'])
def test_invalid_answer_is_counted_not_crashing(bad, rules):
    llm.set_client(FakeClient([bad]))
    assert llm.scan_source(CODE, "d.php", rules) == []
    assert llm.USAGE.invalid_responses == 1


def test_hallucinated_line_or_rule_is_dropped(rules):
    llm.set_client(FakeClient([answer({"line": 99, "rule_id": "PHP-SQLI-001"},
                                      {"line": 2, "rule_id": "PHP-XSS-999"},
                                      {"line": "3", "rule_id": "PHP-SQLI-001"})]))
    assert llm.scan_source(CODE, "e.php", rules) == []
    assert llm.USAGE.dropped_findings == 3


def test_cache_avoids_second_call(rules):
    client = FakeClient([answer()])
    llm.set_client(client)
    llm.scan_source(CODE, "f.php", rules)
    llm.scan_source(CODE, "f.php", rules)
    assert (len(client.prompts), llm.USAGE.calls, llm.USAGE.cache_hits) == (1, 1, 1)


def test_cache_key_depends_on_run(rules, monkeypatch):
    client = FakeClient([answer()])
    llm.set_client(client)
    llm.scan_source(CODE, "g.php", rules)
    monkeypatch.setenv("PHPSCAN_LLM_RUN", "1")
    llm.scan_source(CODE, "g.php", rules)
    assert len(client.prompts) == 2


def test_cost_is_computed():
    u = llm.Usage(input_tokens=1_000_000, output_tokens=1_000_000)
    assert u.cost("claude-haiku-5-5") == pytest.approx(0.60)
    assert u.cost("modele-inconnu") is None


class Temporary(Exception):
    pass


def test_retries_with_exponential_backoff():
    waits, calls = [], iter([Temporary(), Temporary(), "ok"])

    def call():
        v = next(calls)
        if isinstance(v, Exception):
            raise v
        return v

    assert llm.with_retries(call, lambda e: isinstance(e, Temporary), sleep=waits.append) == "ok"
    assert waits == [1.0, 2.0]


def test_gives_up_after_max_attempts_or_on_permanent_error():
    waits = []
    with pytest.raises(llm.LLMError):
        llm.with_retries(lambda: (_ for _ in ()).throw(Temporary()),
                         lambda e: True, sleep=waits.append)
    assert len(waits) == llm.MAX_ATTEMPTS - 1
    with pytest.raises(llm.LLMError):
        llm.with_retries(lambda: (_ for _ in ()).throw(ValueError()), lambda e: False)


def test_api_failure_skips_file_without_crashing(rules):
    class Failing(FakeClient):
        def complete(self, prompt):
            raise llm.LLMError("429 trop de requêtes")

    llm.set_client(Failing([answer()]))
    assert llm.scan_source(CODE, "h.php", rules) == []
    assert len(llm.USAGE.errors) == 1


def test_missing_api_key_stops_with_clear_message(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)               # pas de .env ici
    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        llm.get_client()


def test_dotenv_does_not_override_environment(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# commentaire\nPHPSCAN_TEST_A='depuis-env'\nPHPSCAN_TEST_B=fichier\n")
    monkeypatch.setenv("PHPSCAN_TEST_B", "deja-defini")
    monkeypatch.delenv("PHPSCAN_TEST_A", raising=False)
    llm.load_dotenv(env)
    import os
    assert os.environ["PHPSCAN_TEST_A"] == "depuis-env"
    assert os.environ["PHPSCAN_TEST_B"] == "deja-defini"


def test_metrics_with_fake_llm_and_stability(tmp_path, monkeypatch, capsys):
    (tmp_path / "v.php").write_text("<?php\neval($x); // EXPECT: PHP-EXEC-001\n")
    llm.set_client(FakeClient([answer({"line": 2, "rule_id": "PHP-EXEC-001"})]))
    rep = evaluate(tmp_path, "llm")
    assert (rep.total.vp, rep.total.fp, rep.total.fn) == (1, 0, 0)
    assert stability([rep, rep]) == 1.0
    assert main([str(tmp_path), "--engine", "llm", "--runs", "2"]) == 0
    assert "stabilité" in capsys.readouterr().out


def test_rule_engines_resist_prompt_injection():
    """Regex et AST ignorent les commentaires : ils ne peuvent pas être manipulés."""
    from pathlib import Path
    root = Path(__file__).parent / "injection"
    assert evaluate(root, "ast").total.recall == 1.0


def test_real_client_classifies_errors():
    anthropic = pytest.importorskip("anthropic")
    c = llm.AnthropicClient("claude-haiku-5-5", api_key="sk-ant-factice")

    def err(cls, code=None):
        e = cls.__new__(cls)           # sans requête HTTP réelle
        e.status_code = code
        return e

    assert c._retryable(err(anthropic.RateLimitError, 429))
    assert c._retryable(err(anthropic.InternalServerError, 500))
    assert not c._retryable(err(anthropic.BadRequestError, 400))
    assert not c._retryable(err(anthropic.AuthenticationError, 401))
    fatal = llm.LLMError("x")
    fatal.__cause__ = err(anthropic.AuthenticationError, 401)
    assert c.is_fatal(fatal)


def test_schema_constrains_rule_ids():
    item = llm.RESPONSE_SCHEMA["properties"]["findings"]["items"]
    assert item["properties"]["rule_id"]["enum"] == llm.RULE_IDS


def test_fatal_error_stops_scan(rules):
    class Refused(FakeClient):
        def complete(self, prompt):
            raise llm.LLMError("401")

        def is_fatal(self, err):
            return True

    llm.set_client(Refused([answer()]))
    with pytest.raises(SystemExit, match="clé API refusée"):
        llm.scan_source(CODE, "i.php", rules)
