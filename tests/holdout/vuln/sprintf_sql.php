<?php
$q = sprintf("SELECT * FROM produits WHERE cat = '%s'", $_GET['cat']);
$pdo->query($q); // EXPECT: PHP-SQLI-001
