<?php
function afficher($nom) {
    echo "Bonjour $nom"; // EXPECT: PHP-INPUT-001
}
afficher($_GET['nom']);
