<?php
if (md5($pwd) === $row['hash']) { // EXPECT: PHP-HASH-001
    login();
}
