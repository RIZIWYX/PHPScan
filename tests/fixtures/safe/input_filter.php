<?php
$age = filter_input(INPUT_GET, 'age', FILTER_VALIDATE_INT);
echo $age;
