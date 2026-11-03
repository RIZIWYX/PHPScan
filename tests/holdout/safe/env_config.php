<?php
$config = [
    'db_password' => $_ENV['DB_PASSWORD'] ?? '',
    'api_key' => getenv('API_KEY'),
];
