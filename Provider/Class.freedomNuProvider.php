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

    $uri = sprintf("%s://%s:%s/", ($ssl? 'ldaps' : 'ldap'), $host, $port);

    // Check if the user already exists in Freedom and has a valid LDAP_DN
    $dnu = "";
    $u = new User();
    if( $u->SetLoginName($username) ) {   
      $du = new_Doc($dbaccess, $u->fid);
      if ($du->isAlive()) {
	$dnu = $du->getValue("ldap_dn");
      }
    }
    
    if( $dnu == "" ) {
      // Search user DN in LDAP
      $r = searchLDAPFromLogin($username, false, $info);
      if( count($info) <= 0 ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("search for user '%s' returned empty result!", $username));
	return false;
      }
      if( count($info) > 1 ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("search for user '%s' returned more than one result!", $username));
	return false;
      }
      $dnu = $info[0]['distinguishedName'];
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("found DN '%s' for user with login '%s'", $dnu, $username));
      
      // Check credential
      $ret = $this->checkBindLdap($uri, $dnu, $password);
      if( $ret === false ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("pre-creation authentication failed for user with DN '%s'!", $dnu));
	return false;
      }
      
      // Check if automatic creation is allowed for this provider
      if( ! $this->canICreateUser() ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("authentication failed for user with login '%s' because auto-creation is disabled!", $username));
	return FALSE;
      }
      
      // Create Freedom account
      $err = $this->initializeUser($username);
      if( $err != "" ) {
	error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error creating user '%s' err=[%s]", $username, $err));
	return FALSE;
      }
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Initialized user '%s' from LDAP!", $username));
      
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
    
    $ret = $this->checkBindLdap($uri, $dnu, $password);
    if( $ret === false ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Authentication failed for user '%s'!", $username));
      return false;
    }
    
    return true;
  }
  
  /**
   * Connect to LDAP uri
   */
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

  /**
   * Perform a LDAP bind
   */
  public function bindLdap($conn, $bindDn, $bindPassword) {
    if( $bindDn == '' ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Empty bindDN supplied"));
      return false;
    }

    if( array_key_exists('fix_euro', $this->parms) && strtolower($this->parms{'fix_euro'}) == 'yes' ) {
      $bindPassword = preg_replace("/\xac/", "\x80", $bindPassword);
    }
    if( array_key_exists('convert_to_utf8', $this->parms) && strtolower($this->parms{'convert_to_utf8'}) == 'yes' ) {
      $bindPassword = iconv('WINDOWS-1252', 'UTF-8', $bindPassword);
    }

    $bind = @ldap_bind($conn, $bindDn, $bindPassword);
    if( $bind === false ) {
      error_log(__CLASS__."::".__FUNCTION__." ".sprintf("Error binding with DN '%s'", $bindDn));
      return false;
    }

    return true;
  }

  /**
   * Connect to a LDAP uri and perform a LDAP bind
   */
  public function checkBindLdap($uri, $bindDn, $bindPassword) {
    $conn = $this->openLdap($uri);
    if( $conn == false ) {
      return false;
    }
    $bind = $this->bindLdap($conn, $bindDn, $bindPassword);
    if( $bind == false ) {
      ldap_close($conn);
      return false;
    }
    ldap_close($conn);
    return true;
  }

  public function validateAuthorization($opt) {
    return TRUE; 
  }

  public function initializeUser($username) {
    @include_once('WHAT/Class.User.php');
    @include_once('FDL/Class.Doc.php');
    @include_once('WHAT/Class.Session.php');
    
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