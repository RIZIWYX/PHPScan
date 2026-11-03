<?php
$pages = ['accueil', 'contact'];
$p = in_array($_GET['p'] ?? '', $pages, true) ? $_GET['p'] : 'accueil';
include __DIR__ . "/pages/$p.php";
