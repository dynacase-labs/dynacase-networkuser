<?php
/**
 * Main access when Active directory authentication
 *
 * All HTTP requests call index.php to execute action within application
 *
 * @author Anakeen 2007
 * @version $Id: nu.php,v 1.2 2007/01/25 14:33:46 eric Exp $
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
  include_once('Class.User.php');
  include_once('Class.Session.php');
  $u = new User();
  if ($u->SetLoginName($login)) {
    // already exists
  } else {
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
   
      $u->firstname='eric';
      $u->lastname='Dupont';
      $u->login=$login;
      $u->password_new=uniqid("ad");
      $u->iddomain="0";
      $u->famid="ADUSER";
      $err=$u->Add();
      if ($err != "") {
	print sprintf(_("cannot create user %s: %s"),$login,$err);
	exit(1);
      }	
      
      include_once("FDL/Class.DocFam.php");
      $dbaccess=getParam("FREEDOM_DB");
      $u=new_doc($dbaccess,$u->fid);
      $u->refreshFromAD();
      
    } else {
	print sprintf(_("user %s not exists for FREEDOM"),$login);      
	exit(1);
    }   
  }  
 }

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
$u=new_doc($dbaccess,$u->fid);
$u->refreshFromAD();

/*$dnmembers=$info["memberof"];
print "<h1>search $dnmembers</h1>";
include_once("FDLGEN/Class.Doc5273.php");
_ADGROUP::getADGroup($dnmembers,$info2);
print_r2($info2);
*/

exit;
// ---------------------------- END TEST PART

include('WHAT/index.php');

?>