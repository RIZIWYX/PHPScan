<?php
$id = $_GET['id'];
$res = mysqli_query($db, "SELECT * FROM users WHERE id = " . $id); // EXPECT: PHP-SQLI-001
