# phpscan

> **Outil pédagogique.** phpscan n'a pas vocation à remplacer Semgrep, Bandit ou un audit de sécurité professionnel. Il sert à comprendre comment fonctionne une analyse statique de sécurité, et à mesurer honnêtement ses limites.

Analyseur statique qui scanne du code PHP et signale des motifs à risque : injections SQL par concaténation, exécution de code ou de commandes, secrets en dur, hachage faible de mots de passe, entrées utilisateur non filtrées.

Trois moteurs à comparer sur le même code :
- **regex** : rapide, simple, nombreux faux positifs
- **ast** : arbre syntaxique PHP via tree-sitter + suivi de données souillées (taint)
- **llm** : analyse par un modèle de langage, pour comparaison

## Installation

```bash
git clone https://github.com/RIZIWYX/phpscan.git
cd phpscan
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -e ".[dev]"
```

## Utilisation

```bash
phpscan chemin/vers/projet
phpscan chemin/vers/projet --format json -o rapport.json
phpscan chemin/vers/projet --format sarif -o rapport.sarif
phpscan chemin/vers/projet --engine ast --min-severity MEDIUM
```

Code de sortie : `0` si aucune alerte au-dessus du seuil, `1` sinon (utilisable en CI).

## Règles

| ID | Règle | Sévérité | CWE |
| --- | --- | --- | --- |
| PHP-SQLI-001 | SQL construit par concaténation | HIGH | CWE-89 |
| PHP-EXEC-001 | eval / exec / system / shell_exec | HIGH | CWE-95, CWE-78 |
| PHP-SECRET-001 | Secret en dur | MEDIUM | CWE-798 |
| PHP-HASH-001 | md5 / sha1 pour un mot de passe | HIGH | CWE-916 |
| PHP-INPUT-001 | `$_GET` / `$_POST` utilisé sans filtrage | MEDIUM | CWE-20 |

Le détail de chaque règle (pourquoi c'est risqué, exemple vulnérable, correction) est dans [docs/RULES.md](docs/RULES.md).

## Démo sur Yappli vulnérable

_À compléter (phase 7) : sortie de phpscan sur la version vulnérable de Yappli, puis sur la version corrigée._

## Résultats et métriques

_À compléter (phases 5, 6 et 7 bis)._

| Moteur | Précision | Rappel | Temps / fichier |
| --- | --- | --- | --- |
| regex | - | - | - |
| ast | - | - | - |
| llm | - | - | - |
| Semgrep (p/php) | - | - | - |

## Limites

- Analyse intraprocédurale uniquement : pas de suivi entre fonctions ni entre fichiers.
- Les regex ne comprennent pas la structure du code (faux positifs dans les chaînes, appels sur plusieurs lignes).
- Pas de prise en charge des frameworks (Laravel, Symfony) ni de leurs fonctions d'échappement.
- Le moteur LLM est non déterministe, coûteux et sensible à l'injection de prompt.

## Ignorer une alerte

Ajouter `// phpscan-ignore` en fin de ligne.

## Roadmap

- [ ] Phase 0 - Préparation du dépôt
- [ ] Phase 1 - Chargement des fichiers
- [ ] Phase 2 - Règles en YAML
- [ ] Phase 3 - Moteur regex + 5 règles
- [ ] Phase 4 - Rapports console, JSON, SARIF
- [ ] Phase 5 - Jeu de test et métriques
- [ ] Phase 6 - Moteur AST (tree-sitter + taint)
- [ ] Phase 7 - Démo sur Yappli vulnérable
- [ ] Phase 7 bis - Comparaison avec un LLM
- [ ] Phase 8 - Comparaison Semgrep, README, CI

## Licence

MIT - Rayane Graïne
