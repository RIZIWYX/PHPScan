<?php
// La variable $nom est déjà échappée par le middleware global (voir securite.php),
// l'afficher directement est donc sûr.
$nom = $_GET['nom'];
echo "Bonjour $nom"; // EXPECT: PHP-INPUT-001
