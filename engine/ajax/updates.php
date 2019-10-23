<?php
/*
=====================================================
 DataLife Engine - by SoftNews Media Group 
-----------------------------------------------------
 http://dle-news.ru/
-----------------------------------------------------
 Copyright (c) 2004-2019 SoftNews Media Group
=====================================================
 This code is protected by copyright
=====================================================
 File: updates.php
-----------------------------------------------------
 Use: Check for new versions
=====================================================
*/

if(!defined('DATALIFEENGINE')) {
	header( "HTTP/1.1 403 Forbidden" );
	header ( 'Location: ../../' );
	die( "Hacking attempt!" );
}

if(($member_id['user_group'] != 1)) {die ("error");}

if( $_REQUEST['user_hash'] == "" OR $_REQUEST['user_hash'] != $dle_login_hash ) {

	echo $lang['sess_error'];
	die();

}

echo 'Проверка обновлений выключена.';

?>
