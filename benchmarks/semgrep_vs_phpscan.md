# Reproduire la comparaison avec Semgrep

Versions utilisées : Semgrep 1.183.0, règles PHP communautaires de
[semgrep-rules](https://github.com/semgrep/semgrep-rules) (dossier `php/`, commit `16b9e6d`,
octobre 2026), soit le contenu du jeu de règles `p/php`.

```bash
pip install semgrep
git clone --depth 1 https://github.com/semgrep/semgrep-rules
mkdir regles-php && find semgrep-rules/php -name '*.yaml' ! -name '*.test.yaml' -exec cp {} regles-php/ \;

# Semgrep ignore par défaut les dossiers « tests/ » : on analyse une copie
mkdir cas && cp -r tests/fixtures tests/holdout tests/injection cas/
semgrep --config regles-php cas --metrics=off

# Yapply, branche main
git clone https://github.com/RIZIWYX/Yapply
semgrep --config regles-php Yapply --metrics=off
phpscan Yapply --engine ast
```
