<?php
$id = intval($_GET['id']);
$res = mysqli_query($db, "SELECT * FROM t WHERE id = " . $id);
