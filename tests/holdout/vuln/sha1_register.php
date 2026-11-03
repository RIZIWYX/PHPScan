<?php
$hash = sha1($_POST['password'] . $sel); // EXPECT: PHP-HASH-001
