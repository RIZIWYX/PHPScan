<?php
$id = $_GET['id'];
$sql = <<<SQL
SELECT * FROM t WHERE id = $id
SQL;
mysqli_query($db, $sql); // EXPECT: PHP-SQLI-001
