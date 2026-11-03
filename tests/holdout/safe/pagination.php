<?php
$page = max(1, (int) ($_GET['page'] ?? 1));
$offset = ($page - 1) * 20;
$res = mysqli_query($db, "SELECT * FROM articles LIMIT 20 OFFSET $offset");
