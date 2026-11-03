<?php
$nom = $_POST['nom'];
$r = mysqli_query($db, "SELECT * FROM users WHERE nom = '$nom'"); // EXPECT: PHP-SQLI-001
