<?php
$autorises = ['accueil', 'profil'];
$cible = $_GET['p'] ?? 'accueil';
if (!in_array($cible, $autorises, true)) { $cible = 'accueil'; }
include "pages/$cible.php";
