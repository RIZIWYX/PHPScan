<?php
echo "Bonjour " . htmlspecialchars($_GET['nom'] ?? '', ENT_QUOTES, 'UTF-8');
