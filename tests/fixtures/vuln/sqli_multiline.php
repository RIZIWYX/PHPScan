<?php
$res = mysqli_query(
    $db,
    "SELECT * FROM t WHERE id = " . $_GET['id'] // EXPECT: PHP-SQLI-001
);
