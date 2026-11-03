<?php
$out = shell_exec("ls " . $_GET['dir']); // EXPECT: PHP-EXEC-001
