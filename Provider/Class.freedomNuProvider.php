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

    // retrieve user DN
    $dnu = "";
    $u = new User();
    if( $u->SetLoginName($username) ) {   
      $du = new_Doc($dbaccess, $u->fid);
      if ($du->isAlive()) {
	$dnu = $du->getValue("ldap_dn");
      }
    }
   
    if( $dnu == "" ) {
      // Check if automatic creation is allowed for this provider
      if( ! $this->canICreateUser() ) {
	// Auto-creation not allowed
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("authentication failed for user with login '%s' because auto-creation is disabled!", $username));
	return FALSE;
      }

      // Search user in LDAP and create Freedom LDAPUSER document
      $r = searchLDAPFromLogin($username, false, $info);
      if (count($info)==1 && $info[0]['sAMAccountName']==$username) {
	$err = $this->initializeUser($username);
	if( $err != "" ) {
	  error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error creating user '%s' err=[%s]", $username, $err));
	  return FALSE;
	}
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Initialized user '%s' from LDAP!", $username));
      } else {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Could not find user '%s' in LDAP!", $username));
	return FALSE;
      }
      
      $dnu = "";
      $u = new User();
      if( $u->SetLoginName($username) ) {
	$du = new_Doc($dbaccess, $u->fid);
	if( $du->isAlive() ) {
	  $dnu = $du->getValue("ldap_dn");
	}
      }
      
      if( $dnu == "" ) { 
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Could not find ldap_dn for user '%s'!", $username));
	return FALSE;
      }
    }

    if ($dnu!="") {
      $uri = sprintf("%s://%s:%s/", ($ssl? 'ldaps' : 'ldap'), $host, $port);

      $conn = $this->openLdap($uri);
      if( $conn === false ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error connecting to '%s'", $uri));
	return false;
      }

      $bind = $this->bindLdap($conn, $dnu, $password, true);
      if( $bind === false ) {
	$err = ldap_error($conn);
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("LDAP bind failed for user '%s' (err=[%s])", $username, $err));
	ldap_close($conn);
	return false;
      }

      ldap_close($conn);
      return true;
    }

    error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Could not find a valid user with login '%s'!", $username));
    return false;
  }
  

  public function openLdap($uri) {
    $conn = ldap_connect($uri);
    if( $conn === false ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error connecting to '%s'", $ldapUri));
      return false;
    }

    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);

    $opts = $this->parms{'options'};
    if( is_array($opts) ) {
      foreach ($opts as $k => $v) {
	ldap_set_option($conn, $k, $v);
      }
    }

    return $conn;
  }

  public function bindLdap($conn, $bindDn, $bindPassword, $fix_password = false) {
    if( $fix_password && array_key_exists('fix_euro', $this->parms) && strtolower($this->parms{'fix_euro'}) == 'yes' ) {
      $bindPassword = preg_replace("/\xac/", "\x80", $bindPassword);
    }
    if( $fix_password && array_key_exists('convert_to_utf8', $this->parms) && strtolower($this->parms{'convert_to_utf8'}) == 'yes' ) {
      $bindPassword = iconv('WINDOWS-1252', 'UTF-8', $bindPassword);
    }

    $bind = @ldap_bind($conn, $bindDn, $bindPassword);
    if( $bind === false ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error binding with DN '%s' and password '%s'", $bindDn, $bindPassword));
      return false;
    }

    return true;
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
    if ($err != "") {
      $core->session->close();
      return sprintf(_("cannot create user %s: %s"),$username,$err);
    }
    
    include_once("FDL/Class.DocFam.php");
    $dbaccess=getParam("FREEDOM_DB");

    $du= new_doc($dbaccess,$wu->fid);
    if (!$du->isAlive()) {
      $err=$wu->delete();
      $core->session->close();
      return sprintf(_("cannot create user %s: %s"),$login,$err." (freedom)");
    }

    $du->setValue("us_whatid",$wu->id);
    $err = $du->modify();
    if( $err != "" ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error modifying user '%s' err=[%s]", $username, $err));
      $core->session->close();
      return $err;
    }

    $err = $du->refreshFromLDAP();
    if( $err != "" ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error refreshing user '%s' from LDAP err=[%s]", $username, $err));
      $core->session->close();
      return $err;
    }

    $err = $du->refresh();
    if( $err != "" ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error refreshing user '%s' err=[%s]", $username, $err));
      $core->session->close();
      return $err;
    }

    $core->session->close();    
    return $err;
  }
  
}
?>