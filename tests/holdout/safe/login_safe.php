<?php
$stmt = $pdo->prepare("SELECT hash FROM users WHERE login = ?");
$stmt->execute([$_POST['login']]);
if (password_verify($_POST['mdp'], $stmt->fetchColumn())) { echo "ok"; }
