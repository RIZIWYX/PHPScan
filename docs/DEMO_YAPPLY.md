# Démo : phpscan sur Yapply

[Yapply](https://github.com/RIZIWYX/Yapply) est un petit réseau social en PHP réalisé en
groupe, volontairement sans sécurité sur sa branche `main`. Un
[audit de sécurité manuel](https://github.com/RIZIWYX/Yapply/blob/main/doc/AUDIT_SECURITE_YAPPLY.md)
y a recensé 12 failles (F-01 à F-12). C'est un vrai projet, que ni les règles ni les moteurs
de phpscan n'ont vu pendant leur écriture : un bon test grandeur nature.

Version analysée : branche `main`, commit `1a9237e`, 17 fichiers PHP.

## Reproduire

```bash
git clone https://github.com/RIZIWYX/Yapply
phpscan Yapply --engine regex
phpscan Yapply --engine ast
```

## Résultats

| Moteur | Alertes | Vraies failles | Faux positifs |
| --- | --- | --- | --- |
| regex | 0 | 0 | 0 |
| ast | 7 | 7 | 0 |

Les 7 alertes AST sont des **XSS réfléchies** (PHP-INPUT-001) : une valeur envoyée par
formulaire est réaffichée telle quelle dans la page.

| Fichier:ligne | Source | Affichage |
| --- | --- | --- |
| `app/message.php:37` | `$autre = $_POST['avec']` | `echo "Aucune discussion trouvée avec $autre."` |
| `app/message.php:55` | `$autre` | `value="<?php echo $autre; ?>"` (dans un attribut HTML) |
| `app/amis.php:25` | `$ami = trim($_POST['username'])` | `echo "<h2>$ami est déjà dans votre liste d'amis.</h2>"` |
| `app/amis.php:30` | `$ami` | `echo "<h2>$ami a été ajouté à vos amis !</h2>"` |
| `app/profil.php:44` | `$username = $_POST['username']` | `echo "<h3>Posts de $username :</h3>"` |
| `app/profil.php:58` | `$username` | `value='$username'` dans un formulaire |
| `app/profil.php:59` | `$username` | `value='$username'` dans un formulaire |

Exemple d'exploitation : un formulaire piégé qui envoie `username=<script>...</script>` à
`profil.php` exécute le script dans le navigateur de la victime.

Ces XSS **réfléchies ne sont pas citées dans l'audit manuel** : sa faille F-06 décrit la
XSS stockée (bio, posts, messages) sans mentionner ces réaffichages de paramètres de
formulaire. L'outil complète donc l'audit humain sur ce point.

### Pourquoi la regex ne trouve rien

Le code de Yapply passe toujours par une variable avant d'afficher :

```php
$ami = trim($_POST['username']);   // ligne 13
// ...
echo "<h2>$ami a été ajouté à vos amis !</h2>";   // ligne 30
```

La règle regex cherche `echo` et `$_GET[`/`$_POST[` dans la même instruction. Elle ne voit
jamais les deux ensemble. Le suivi de souillure de l'AST relie la ligne 13 à la ligne 30.
C'est exactement le faux négatif mesuré sur le jeu de test (`input_var_then_echo.php`), mais
cette fois sur du vrai code : 0 alerte contre 7.

## Un bug trouvé grâce à Yapply

La première analyse donnait 9 alertes, dont une fausse :

```php
// app/accueil.php:10
$post_commente = (isset($_POST['post_id']) && $_POST['post_id'] !== '')
    ? (int) $_POST['post_id'] : null;
```

La valeur est protégée par le cast `(int)`, mais le moteur considérait que `$_POST` présent
dans la **condition** du ternaire souillait le résultat. Or la valeur d'un ternaire vient de
ses branches, jamais de sa condition. Corrigé dans `engine_ast.py`, avec deux tests de
non-régression. Les métriques des jeux de développement et de validation sont inchangées.

Effet secondaire honnête : l'alerte `accueil.php:160` (`echo $champs[$i]`) a disparu avec
la correction. C'est pourtant une vraie faille (la XSS stockée F-06), mais elle était
signalée pour une mauvaise raison : le moteur ne modélise pas les données lues dans un
fichier comme une source.

## Ce que phpscan ne voit pas

Sur les 12 failles de l'audit, aucune n'est détectée. C'est attendu : elles sortent des
5 règles de phpscan.

| Faille de l'audit | Pourquoi phpscan la rate |
| --- | --- |
| F-01 Upload non restreint | aucune règle sur `move_uploaded_file` |
| F-02 Mots de passe en clair | la règle PHP-HASH-001 détecte un hachage faible, pas l'absence de hachage |
| F-03 Sessions cassées | défaut de conception, pas un motif de code |
| F-04 Injection de séparateur | format de fichier maison (`|`), propre à l'application |
| F-05 `data/` exposé sur le web | configuration du serveur, pas du code |
| F-06 XSS stockée | les lectures de fichiers (`file()`, `file_get_contents`) ne sont pas des sources |
| F-07 Pas de CSRF | une absence de code ne se détecte pas par motif |
| F-08 Path traversal | aucune règle : `$_POST` dans un chemin de `file_put_contents` / `fopen` |
| F-09 à F-12 | failles de logique métier |

C'est la principale leçon de cette démo : **un analyseur statique à règles trouve des
motifs, pas des défauts de conception**. Il complète un audit humain, il ne le remplace pas.

## Pistes d'amélioration

- Règle **path traversal** (CWE-22) : donnée souillée dans un chemin de fichier
  (`fopen`, `file_put_contents`, `file`, `include`). Le moteur de souillure existe déjà,
  il suffit d'ajouter ces sinks. Elle détecterait F-08 (`message.php`) et `amis.php:29`.
- **Sources de second ordre** : traiter le contenu lu dans un fichier ou une base comme
  souillé, pour détecter la XSS stockée F-06.
- Règle **upload** : `move_uploaded_file` sans vérification du type ni de l'extension (F-01).
