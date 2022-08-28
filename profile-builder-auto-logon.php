<?php
/*
* Plugin Name: PFS-Profile Builder Auto Logon
* Description: This plugin will make Profile Builder automatically logon to the page /account-management/ac when confirming a new users email address.
* Version: 1.0.0
* Author: Pink Fizz Social
* Author URI: http://pinkfizz.social
* License: GPL2
*/

/*
 * Auto Login After Email Confirmation. Tags auto login, email confirmation
 */
 
add_action( 'wppb_activate_user', 'wppb_custom_autologin_redirect', 10, 3 );
function wppb_custom_autologin_redirect( $user_id, $password, $meta ){
	// hack to fix conflict with WP Voting Contest in C:\www\pb20\wp-content\plugins\wp-voting-contest\includes\votes-save.php lines 420, 421, 422
	// basically WP Voting Contenst will login any email field that's submitted via POST. So we're overwriting the global $current_user for this particular instance.
	global $current_user;
	$current_user = 0;
 
	$token = wppb_create_onetime_token( 'pb_autologin_'.$user_id, $user_id );
 
 	$location = add_query_arg( array(
    	'pb_autologin' => 'true',
    	'pb_uid'       => $user_id,
    	'pb_token'     => $token,
	), home_url());
 
	echo "<script> window.location.replace('$location'); </script>";
}
 
add_action( 'init', 'wppb_custom_autologin' );
function wppb_custom_autologin(){
	if( isset( $_GET['pb_autologin'] ) && isset( $_GET['pb_uid'] ) &&  isset( $_GET['pb_token'] )  ){
		$uid = $_GET['pb_uid'];
		$token  = $_GET['pb_token'];
		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		$wp_hasher = new PasswordHash(8, TRUE);
		$time = time();
 
		$hash_meta = get_user_meta( $uid, 'pb_autologin_' . $uid, true);
		$hash_meta_expiration = get_user_meta( $uid, 'pb_autologin_' . $uid . '_expiration', true);
 
		if ( ! $wp_hasher->CheckPassword($token . $hash_meta_expiration, $hash_meta) || $hash_meta_expiration < $time  ){
			//wp_redirect( $current_page_url . '?wpa_error_token=true' );
			die (' You are not allowed to do that. ');
			exit;
		} else {
			wp_set_auth_cookie( $uid );
			delete_user_meta($uid, 'pb_autologin' . $uid );
			delete_user_meta($uid, 'pb_autologin' . $uid . '_expiration');
			wp_redirect( home_url() . '/account-management/ac' );
			exit;
		}
	}
}
 
function wppb_create_onetime_token( $action = -1, $user_id = 0 ) {
	$time = time();
 
	// random salt
	$key = wp_generate_password( 20, false );
 
	require_once( ABSPATH . 'wp-includes/class-phpass.php');
	$wp_hasher = new PasswordHash(8, TRUE);
	$string = $key . $action . $time;
 
	// we're sending this to the user
	$token  = wp_hash( $string );
	$expiration = $time + 60*10;
	$expiration_action = $action . '_expiration';
 
	// we're storing a combination of token and expiration
	$stored_hash = $wp_hasher->HashPassword( $token . $expiration );
 
	update_user_meta( $user_id, $action , $stored_hash ); // adjust the lifetime of the token. Currently 10 min.
	update_user_meta( $user_id, $expiration_action , $expiration );
	return $token;
}