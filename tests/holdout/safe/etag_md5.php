<?php
$etag = md5(file_get_contents($fichier));
header("ETag: $etag");
