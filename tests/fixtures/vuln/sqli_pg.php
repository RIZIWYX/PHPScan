<?php
$q = pg_query($conn, "SELECT * FROM a WHERE b = " . $b); // EXPECT: PHP-SQLI-001
