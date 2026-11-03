<?php
$login = $_POST['login'];
$mdp = $_POST['mdp'];
$sql = "SELECT * FROM users WHERE login = '$login' AND mdp = '" . md5($mdp) . "'"; // EXPECT: PHP-HASH-001
$res = mysqli_query($cnx, $sql); // EXPECT: PHP-SQLI-001
