<?php
/**
 * User manipulation
 *
 * @author Anakeen 2004
 * @version $Id: Method.LDAPUser.php,v 1.1 2007/01/23 17:02:53 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM
 * @subpackage USERCARD
 */
 /**
 */

var $defaultview="FDL:VIEWBODYCARD"; // use default view
function RefreshDocUser() {
  parent::RefreshDocUser();

  $err=$this->getADUser($this->getValue('us_login'),$info);
  print_r2($info);
  //var_dump (xdebug_get_function_stack());		 

  $ldapmap=$this->getMapAttributes();
  // print_r2($ldapmap);
  foreach ($ldapmap as $k=>$v) {
    if ($v["ldapname"] && $v["ldapmap"] && ($v["ldapmap"][0]!=':') && ($info[strtolower($v["ldapname"])])) {
      $val=$info[strtolower($v["ldapname"])];
      $att=$v["ldapmap"];
      $this->setValue($att,$val);
      print "$att:[$val]<br>";
    }
  }
  $this->modify();
  
}

/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getADUser($login,&$info) {
  $ldaphost="ad.tlse.i-cesam.com";
  $ldapbase="dc=ad,dc=tlse,dc=i-cesam,dc=com";
  $ldappw="anakeen";
  $ldapbinddn="cn=administrateur,cn=users,dc=ad,dc=tlse,dc=i-cesam,dc=com";
  $ldapbindloginattribute="sAMAccountName";

  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    $sr=ldap_search($ds, "$ldapbase", "$ldapbindloginattribute=$login"); 

    $count= ldap_count_entries($ds, $sr);
    if ($count==1) {
      $info1 = ldap_get_entries($ds, $sr);
      $info0=$info1[0];
      //      print "<pre>";print_r($info);print "</pre>";
      foreach ($info0 as $k=>$v) {
	if (! is_numeric($k)) {
	  if ($v["count"]==1)  $info[$k]=$v[0];
	  else {
	    //	    unset($v["count"]);
	    if (is_array($v))  unset($v["count"]);   
	    $info[$k]=$v;
	  }
	}
      }
      
    } else {
      if ($count==0) $err=sprintf(_("Cannot find user [%s]"),$login);
      else $err=sprintf(_("Find mutiple user with same login  [%s]"),$login);
    }

    
    ldap_close($ds);

  } else {
    $err=sprintf(_("Unable to connect to LDAP server %s"),$ldaphost);
  }

  return $err;
  
}

?>