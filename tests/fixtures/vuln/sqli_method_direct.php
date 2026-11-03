<?php
$db->query("SELECT * FROM users WHERE login = '" . $_POST['login'] . "'"); // EXPECT: PHP-SQLI-001
