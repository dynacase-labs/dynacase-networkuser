<?php

/**
 * ldap authentication provider
 *
 */
 /**
  */

include_once("WHAT/Class.Provider.php");
Class freedomNuProvider extends Provider {
  
  public function validateCredential($username, $password) {  
    global $action;
    @include_once('WHAT/Class.User.php');
    @include_once('FDL/Class.Doc.php');
    @include_once('NU/Lib.NU.php');


    $db = getParam("FREEDOM_DB");
    $ssl = false;
    $host = getParam("NU_LDAP_HOST", '127.0.0.1');
    $port = '389';
    $root = getParam("NU_LDAP_BINDDN", 'admin');
    $rootpw = getParam("NU_LDAP_PASSWORD", 'admin');

    error_log(__CLASS__."->".__FUNCTION__."($username, $password)");

    // retrieve user DN
    $dnu = "";
    $u = new User();
    if( $u->SetLoginName($username) ) {   
      $du = new_Doc($dbaccess, $u->fid);
      if ($du->isAlive()) {
	$dnu = $du->getValue("ldap_dn");
      }
    }
   
    if ($dnu!="") {
     $uri = sprintf("%s://%s:%s/", ($ssl? 'ldaps' : 'ldap'), $host, $port);
      $r = ldap_connect($uri);
      $err = ldap_get_option($r, LDAP_OPT_PROTOCOL_VERSION, $ret);
      if (!$err) {
	error_log("[$ret] Can't establish LDAP connection : $uri");
	return FALSE;
      }

      ldap_set_option($r, LDAP_OPT_PROTOCOL_VERSION, 3);

      $opts = $this->parms{'options'};
      if (is_array($opts)) {
	foreach ($opts as $k=>$v) {
	  ldap_set_option($r, $k, $v);
	}
      }

      if( array_key_exists('fix_euro', $this->parms) && strtolower($this->parms{'fix_euro'}) == 'yes' ) {
	$password = preg_replace("/\xac/", "\x80", $password);
      }
      if( array_key_exists('convert_to_utf8', $this->parms) && strtolower($this->parms{'convert_to_utf8'}) == 'yes' ) {
	$password = iconv('WINDOWS-1252', 'UTF-8', $password);
      }
      
      $b = @ldap_bind($r, $dnu, $password);
      if ($b) return TRUE;
      else {
	$err = ldap_error($r);
	error_log("user=[$dnu] pass=[*********] result=>".($b?"OK":"NOK")." ($err)");
      }
      return FALSE;    

    } else {

      // Check if automatic creation is allowed for this provider
      if ($this->canICreateUser()) {

	// first check given username and password 
 	$r = searchLDAPFromLogin($username, false, $info);
	if (count($info)==1 && $info[0]['sAMAccountName']==$username) {
	  $err = $this->initializeUser($username);
	  error_log(__CLASS__."::".__FUNCTION__." user $username found in ldap, createion=[$err]");
	}

	
      }
      
    }
    return FALSE;
  }
  
  
  public function validateAuthorization($opt) {
    return TRUE; 
  }


  public function initializeUser($username) {
    
    @include_once('WHAT/Class.User.php');
    @include_once('FDL/Class.Doc.php');
    
    global $action;
    $err = "";
    
    $CoreNull="";
    $core = new Application();
    $core->Set("CORE",$CoreNull);
    $core->session=new Session();
    $action=new Action();
    $action->Set("",$core);
    $action->user=new User("",1); //create user as admin
    
    $wu = new User();
    $wu->firstname='--';
    $wu->lastname='(from ldap/ad) '.$username;
    $wu->login=$username;
    $wu->password_new=uniqid("nu");
    $wu->iddomain="0";
    $wu->famid="LDAPUSER";
    $err=$wu->Add();
    if ($err != "") return sprintf(_("cannot create user %s: %s"),$username,$err);
    
    include_once("FDL/Class.DocFam.php");
    $dbaccess=getParam("FREEDOM_DB");
    $du= new_doc($dbaccess,$wu->fid);
    if (!$du->isAlive()) {
      $err=$wu->delete();
      return sprintf(_("cannot create user %s: %s"),$login,$err." (freedom)");
    }
    $du->setValue("us_whatid",$wu->id);
    $err = $du->modify();
    if ($err=="") {
      $err=$du->refreshFromLDAP();
    }
    $core->session->close();
    
    return $err;
  }
  
}
?>