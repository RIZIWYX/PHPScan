<?php
$cmd = "ping -c 1 " . $_POST['ip'];
$out = shell_exec($cmd); // EXPECT: PHP-EXEC-001
