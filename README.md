# phpscan

[![CI](https://github.com/RIZIWYX/PHPScan/actions/workflows/ci.yml/badge.svg)](https://github.com/RIZIWYX/PHPScan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Sortie](https://img.shields.io/badge/rapports-console%20%7C%20JSON%20%7C%20SARIF-informational)
![Statut](https://img.shields.io/badge/statut-en%20d%C3%A9veloppement-yellow)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

![Démo : analyse de fichiers PHP vulnérables, rapport JSON et tests](docs/demo.gif)

> **Outil pédagogique.** phpscan n'a pas vocation à remplacer Semgrep, Bandit ou un audit de sécurité professionnel. Il sert à comprendre comment fonctionne une analyse statique de sécurité, et à mesurer honnêtement ses limites.

Analyseur statique qui scanne du code PHP et signale des motifs à risque : injections SQL par concaténation, exécution de code ou de commandes, secrets en dur, hachage faible de mots de passe, entrées utilisateur non filtrées.

Trois moteurs à comparer sur le même code :
- **regex** *(fonctionnel)* : rapide, simple, nombreux faux positifs
- **ast** *(en cours)* : arbre syntaxique PHP via tree-sitter + suivi de données souillées (taint)
- **llm** *(prévu)* : analyse par un modèle de langage, pour comparaison (le prompt est versionné dans `prompts/`)

## Aperçu

Sortie réelle du moteur regex sur deux fichiers du jeu de test :

```text
$ phpscan tests/fixtures/vuln/sqli_concat.php tests/fixtures/vuln/weak_hash.php
──────────────────────── tests/fixtures/vuln/sqli_concat.php ────────────────────────
HIGH   tests/fixtures/vuln/sqli_concat.php:3  PHP-SQLI-001 Requête SQL construite par concaténation de variables
       $res = mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
       -> Utiliser une requête préparée (PDO::prepare + execute)
───────────────────────── tests/fixtures/vuln/weak_hash.php ─────────────────────────
HIGH   tests/fixtures/vuln/weak_hash.php:2  PHP-HASH-001 md5/sha1 utilisé pour hacher un mot de passe
       $hash = md5($password);
       -> Utiliser password_hash() et password_verify()
─────────────────────────────────────────────────────────────────────────────────────
2 fichier(s) analysé(s), 2 alerte(s) : 2 HIGH
```

Sur le jeu de test actuel (5 fichiers vulnérables, 3 fichiers sains), le moteur regex détecte les **5 vulnérabilités** et produit **1 faux positif** sur un fichier sain : c'est précisément ce que le moteur AST doit corriger.

## Installation

```bash
git clone https://github.com/RIZIWYX/PHPScan.git
cd phpscan
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -e ".[dev,ast]"     # ast = moteur tree-sitter
```

## Utilisation

```bash
phpscan chemin/vers/projet
phpscan chemin/vers/projet --format json -o rapport.json
phpscan chemin/vers/projet --format sarif -o rapport.sarif
phpscan chemin/vers/projet --min-severity MEDIUM   # seulement les alertes MEDIUM et plus
phpscan chemin/vers/projet --engine ast            # moteur AST + suivi de souillure (recommandé)
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

## Structure

```
phpscan/
├── src/phpscan/        # CLI, chargement, moteurs regex / ast / llm, rapports
├── rules/default.yml   # Règles en YAML
├── tests/fixtures/     # Jeu de développement (58 fichiers étiquetés)
├── tests/holdout/      # Jeu de validation (20 fichiers, jamais utilisés pour régler)
├── docs/RULES.md       # Explication de chaque règle
├── benchmarks/         # Comparaison avec Semgrep (à venir)
└── prompts/            # Prompt du moteur LLM
```

## Tests

```bash
pytest          # 128 tests + 24 limites connues (xfail strict)
ruff check .
```

Les cas qu'un moteur rate ou signale à tort sont marqués `xfail(strict=True)` : ils
documentent ses limites, et le test échoue dès qu'une amélioration en corrige un, pour
qu'on mette la liste à jour.

## Deux moteurs

**regex** (`--engine regex`) cherche des motifs dans le texte. Rapide, mais il ne voit pas
la structure du code : il se fait piéger par les chaînes et les commentaires, ne reconnaît
pas les fonctions d'échappement et ne suit pas une valeur d'une ligne à l'autre.

**ast** (`--engine ast`) transforme le code en arbre syntaxique avec
[tree-sitter](https://tree-sitter.github.io/) et suit les données souillées
(*taint tracking*) :

```php
$q = $_GET['q'];                 // source : $q devient souillée
$propre = htmlspecialchars($q);  // sanitizer : $propre est sûre
echo $propre;                    // pas d'alerte
echo "Résultats pour $q";        // $q souillée atteint un sink -> PHP-INPUT-001
```

Sources : `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`. Sanitizers : `htmlspecialchars`,
`intval`, `filter_input`, casts `(int)`/`(float)`, vérification `in_array` en liste blanche...
Sinks : `echo`, `print`, `include`, requêtes SQL, fonctions d'exécution.

## Métriques

Deux jeux de fichiers étiquetés, chaque faille attendue étant marquée sur sa ligne par
`// EXPECT: <règle>` :

- **développement** (`tests/fixtures/`, 58 fichiers) : utilisé pour écrire les règles ;
- **validation** (`tests/holdout/`, 20 fichiers) : écrit après le moteur AST et jamais
  utilisé pour le régler. C'est la mesure qui compte.

```bash
phpscan-metrics --engine ast                  # jeu de développement
phpscan-metrics tests/holdout --engine ast    # jeu de validation
```

| Moteur | Jeu | Précision | Rappel | Temps / fichier |
| --- | --- | --- | --- | --- |
| regex | développement | 67 % | 60 % | ~0,1 ms |
| regex | **validation** | 67 % | **18 %** | ~0,1 ms |
| ast | développement | 100 % | 100 % | ~0,2 ms |
| ast | **validation** | **100 %** | **73 %** | ~0,3 ms |

- **Précision** = VP / (VP + FP) : part des alertes qui sont de vraies failles.
- **Rappel** = VP / (VP + FN) : part des vraies failles détectées.

Lecture honnête : le 100 % sur le jeu de développement est attendu, puisque le moteur a été
écrit en le regardant. Sur le jeu de validation, l'AST détecte 4 fois plus de failles que
la regex sans aucun faux positif. Les jeux restent petits (11 failles en validation) : ces
chiffres comparent deux approches, ils ne mesurent pas un outil de production.

Failles ratées par l'AST sur le jeu de validation :

| Fichier | Cause |
| --- | --- |
| `function_param.php` | la souillure ne traverse pas les appels de fonction |
| `request_array.php` | `$data = $_REQUEST` puis `$data['msg']` : copie de tableau non suivie |
| `config_secret.php` | constantes de classe (`const DB_PASS = ...`) non analysées |

## Limites

- Moteur AST intraprocédural : pas de suivi entre fonctions ni entre fichiers, ni dans les propriétés d'objets et cases de tableaux.
- Les regex ne comprennent pas la structure du code (faux positifs dans les chaînes, appels sur plusieurs lignes).
- Pas de prise en charge des frameworks (Laravel, Symfony) ni de leurs fonctions d'échappement.
- Le moteur LLM est non déterministe, coûteux et sensible à l'injection de prompt.

## Ignorer une alerte

Ajouter `// phpscan-ignore` en fin de ligne.

## Roadmap

- [x] Phase 0 - Préparation du dépôt
- [x] Phase 1 - Chargement des fichiers
- [x] Phase 2 - Règles en YAML
- [x] Phase 3 - Moteur regex + 5 règles
- [x] Phase 4 - Rapports console, JSON, SARIF
- [x] Phase 5 - Jeu de test et métriques
- [x] Phase 6 - Moteur AST (tree-sitter + taint)
- [ ] Phase 7 - Démo sur Yappli vulnérable
- [ ] Phase 7 bis - Comparaison avec un LLM
- [ ] Phase 8 - Comparaison Semgrep (précision, rappel, temps par fichier)

## Licence

Distribué sous licence **MIT**, voir [LICENSE](LICENSE).
