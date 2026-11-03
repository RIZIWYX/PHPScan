<?php
$h = popen("tail -f " . $log, "r"); // EXPECT: PHP-EXEC-001
