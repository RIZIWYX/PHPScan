<?php
$terme = htmlspecialchars($_GET['terme'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<h1>Recherche : <?php echo $terme; ?></h1>
