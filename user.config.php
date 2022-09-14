<?php
/*
	user.config.php
-------------------------------------------------------------------------------*/
$this->config = array(
    'keep_login' => true,               // ブラウザを終了してもログインしたままにするか
    'multi_login' => true,              // 複数端末からのログインを許可するか

    'cookie_u' => 'u',
    'cookie_g' => 'g',
    'cookie_s' => 's',
    'expires' => 3600 * 24 * 30,      // cookie_s: 保存したCookieの有効期限

    'login_url' => '/login.php',      // ログインフォーム
    'logout_url' => 'https://hoge.jp/',  // ログアウトしたときの遷移先

    'db_host' => 'YOUR_DB_HOST',
    'db_user' => 'YOUR_DB_USER',
    'db_pass' => 'YOUR_DB_PASS',
    'db_name' => 'YOUR_DB_NAME',
);
