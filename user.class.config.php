<?php
/*
	user.class.config.php

-------------------------------------------------------------------------------*/
$user_config = array(
    'db_host' => 'DB_HOST',
    'db_user' => 'DB_USER',
    'db_pass' => 'DB_PASS',
    'db_name' => 'DB_NAME',

    'login_form' => '/login.php',     // ログインフォーム
    'logout_location' => 'https://extrick.jp',  // ログアウトしたときの遷移先
    'stay_login' => false,           // ログインしたままにするか
    'multi_login' => true,           // 複数端末からのログインを許可するか
    'expires' => 3600 * 24 * 30,      // 保存したCookieの有効期限

    'cookie_u' => 'u',
    'cookie_g' => 'g',
    'cookie_s' => 's',
);
