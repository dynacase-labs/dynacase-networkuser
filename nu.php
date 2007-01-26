<?php
/**
 * Main access when Active directory authentication
 *
 * All HTTP requests call index.php to execute action within application
 *
 * @author Anakeen 2007
 * @version $Id: nu.php,v 1.3 2007/01/26 16:15:03 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package WHAT
 * @subpackage 
 */
 /**
 */



// if want to create user automatically
$creatuser=true;


$login=$_SERVER['PHP_AUTH_USER'];
if ($login) {  
  
  if (!$sess_num) {
    // verify only  when session is out
    include_once('Class.User.php');
    include_once('Class.Session.php');
    $WHATUSER = new User();
    if ($WHATUSER->SetLoginName($login)) {
      // already exists
            
      // 1. Verify if session expired
      // 2 . If expired Then verify whenChanged and update if needed

    } else {
      // 1. Search SID from login
      // 2. verify if SID exists in FREEDOM
      
      // Create User if not exists
      // Rename login if Exist

      if ($creatuser) {
	// need create him   
      
	global $action;
	$CoreNull="";
	$core = new Application();
	$core->Set("CORE",$CoreNull);
	$core->session=new Session();
	$action=new Action();
	$action->Set("",$core);
	$action->user=new User("",1); //create user as admin
   
	$WHATUSER->firstname='Unknown';
	$WHATUSER->lastname='To Define';
	$WHATUSER->login=$login;
	$WHATUSER->password_new=uniqid("ad");
	$WHATUSER->iddomain="0";
	$WHATUSER->famid="ADUSER";
	$err=$WHATUSER->Add();
	if ($err != "") {
	  print sprintf(_("cannot create user %s: %s"),$login,$err);
	  exit(1);
	}	
      
	include_once("FDL/Class.DocFam.php");
	$dbaccess=getParam("FREEDOM_DB");
	$WHATUSER=new_doc($dbaccess,$WHATUSER->fid);
	$WHATUSER->refreshFromAD();
	$WHATUSER->postModify();
      
      } else {
	print sprintf(_("user %s not exists for FREEDOM"),$login);      
	exit(1);
      }   
    }  
  }
 }
/*
// ---------------------------- TEST PART
if (! $core) {
  global $action;
      $CoreNull="";
      $core = new Application();
      $core->Set("CORE",$CoreNull);
      $core->session=new Session();
      $action=new Action();
      $action->Set("",$core);
      $action->user=new User("",1); //create user as admin     
 }

include_once("FDL/Class.DocFam.php");
$dbaccess=getParam("FREEDOM_DB");
$WHATUSER=new_doc($dbaccess,$WHATUSER->fid);
$WHATUSER->refreshFromAD();




exit;
*/
// ---------------------------- END TEST PART

include('WHAT/index.php');

?>