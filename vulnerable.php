<?php // DEMO FIXTURE
$q = "SELECT * FROM users WHERE name='" . $_GET['n'] . "'";
echo $_GET['n'];
system($_POST['cmd']);
$o = unserialize($_COOKIE['d']);
