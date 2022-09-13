<?php
/*
	user.class.config.php
-------------------------------------------------------------------------------*/
$this->config = array(
    'version' => '3.1.0',

    'stay_login' => true,               // ブラウザを終了してもログインしたままにするか
    'multi_login' => true,              // 複数端末からのログインを許可するか

    'cookie_u' => 'u',
    'cookie_g' => 'g',
    'cookie_s' => 's',
    'expires' => 3600 * 24 * 30,      // cookie_s: 保存したCookieの有効期限

    'login_url' => '/login.php',      // ログインフォーム
    'logout_url' => 'https://hoge.jp/',  // ログアウトしたときの遷移先

    'db_host' => 'DB_HOST',
    'db_user' => 'DB_USER',
    'db_pass' => 'DB_PASS',
    'db_name' => 'DB_NAME',
);
