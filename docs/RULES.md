# Règles de phpscan

Pour chaque règle : pourquoi c'est risqué, un exemple vulnérable, une correction.

## PHP-SQLI-001 - SQL construit par concaténation (CWE-89)

**Risque.** Une entrée utilisateur insérée directement dans une requête permet de modifier la requête (injection SQL) : lecture ou suppression de données, contournement d'authentification.

```php
// Vulnérable
$res = mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);

// Corrigé
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

## PHP-EXEC-001 - Exécution de code ou de commande (CWE-95, CWE-78)

**Risque.** `eval`, `exec`, `system`, `shell_exec`, `passthru` ou les backticks exécutent du code ou une commande système. Avec une donnée contrôlée par l'attaquant, c'est une exécution de code à distance.

```php
// Vulnérable
system("ping " . $_GET['host']);

// Corrigé
if (filter_var($_GET['host'], FILTER_VALIDATE_IP)) {
    system("ping -c 1 " . escapeshellarg($_GET['host']));
}
```

## PHP-SECRET-001 - Secret en dur (CWE-798)

**Risque.** Un mot de passe ou une clé API dans le code finit dans l'historique Git et peut fuiter.

```php
// Vulnérable
$api_key = "sk_live_9f8a7b6c5d4e3f2a1b0c";

// Corrigé
$api_key = getenv("API_KEY");
```

## PHP-HASH-001 - Hachage faible de mot de passe (CWE-916)

**Risque.** md5 et sha1 sont trop rapides : un mot de passe haché ainsi se casse par force brute ou avec des tables précalculées.

```php
// Vulnérable
$hash = md5($password);

// Corrigé
$hash = password_hash($password, PASSWORD_DEFAULT);
password_verify($password, $hash);
```

## PHP-INPUT-001 - Entrée utilisateur non filtrée (CWE-20)

**Risque.** `$_GET`, `$_POST`, `$_REQUEST` ou `$_COOKIE` utilisés directement dans un affichage, une requête ou un `include` ouvrent la porte au XSS, aux injections ou à l'inclusion de fichier.

```php
// Vulnérable
echo "Bonjour " . $_GET['nom'];

// Corrigé
echo "Bonjour " . htmlspecialchars($_GET['nom'], ENT_QUOTES, 'UTF-8');
```
