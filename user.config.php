<?php
/*
	user.config.php
-------------------------------------------------------------------------------*/
$this->config = array(
    'keep_login' => 0,
    'multi_login' => 1,

    'cookie_u' => 'u',
    'cookie_g' => 'g',
    'expires' => 3600 * 24 * 30,      // Expiry time of stored cookies

    'login_url' => '/login.php',      // Login form
    'logout_url' => 'https://hoge.jp/',  // Transition destination when logged out

    'db_host' => 'YOUR_DB_HOST',
    'db_user' => 'YOUR_DB_USER',
    'db_pass' => 'YOUR_DB_PASS',
    'db_name' => 'YOUR_DB_NAME',
);
