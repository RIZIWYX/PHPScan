<?php
if (password_verify($_POST['mdp'], $hash)) { login(); }
