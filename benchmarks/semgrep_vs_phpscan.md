# Comparaison phpscan / Semgrep / LLM

_À compléter en phases 7 bis et 8._

Commandes :

```bash
phpscan tests/fixtures --format json -o phpscan.json
semgrep --config p/php tests/fixtures --json -o semgrep.json
```

| Cas | regex | ast | llm | Semgrep |
| --- | --- | --- | --- | --- |
