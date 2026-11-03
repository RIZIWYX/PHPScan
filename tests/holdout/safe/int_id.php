<?php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) { exit; }
$r = $pdo->query("SELECT * FROM t WHERE id = $id");
