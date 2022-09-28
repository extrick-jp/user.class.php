-- Adminer 4.8.1 MySQL 5.5.5-10.1.48-MariaDB dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `userid` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `loginname` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `auth` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`userid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `user_property`;
CREATE TABLE `user_property` (
  `userid` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `username` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `mailadrs` varchar(255) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`userid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `user_session`;
CREATE TABLE `user_session` (
  `session` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `userid` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `session_expire` int(10) unsigned NOT NULL,
  `keep_login` tinyint(3) unsigned NOT NULL,
  PRIMARY KEY (`session`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


-- 2022-09-28 03:09:03
