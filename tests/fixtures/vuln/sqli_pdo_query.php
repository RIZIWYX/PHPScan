<?php
$sql = "DELETE FROM posts WHERE id = " . $_GET['id'];
$pdo->query($sql); // EXPECT: PHP-SQLI-001
