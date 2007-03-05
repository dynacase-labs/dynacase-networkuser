<?php
/**
 * Active Directory Group manipulation
 *
 * @author Anakeen 2007
 * @version $Id: Method.NU.php,v 1.9 2007/03/05 13:43:07 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 */
 /**
 */


  /**
   * Not write in FREEDOM Ldap
   */
function UseLdap() { return false; }

function refreshFromAD() {
  include_once("NU/Lib.NU.php");
  include_once("NU/Lib.DocNU.php");

  $err=getLDAPFromLogin($this->getValue('us_login'),($this->doctype=='D'),$info);

  $ldapmap=$this->getMapAttributes();
  //   print_r2($ldapmap);
  foreach ($ldapmap as $k=>$v) {    
    if ($v["ldapname"] && $v["ldapmap"] && ($v["ldapmap"][0]!=':') && ($info[strtolower($v["ldapname"])])) {
      $val=$info[strtolower($v["ldapname"])];
      $att=$v["ldapmap"];
      if ($val)  {
	if (seems_utf8($val)) $val=utf8_decode($val);
	$this->setValue($att,$val);
      }
      //if ($val) print "--- $att:$val\n";      
    } //else print "*** ".$v["ldapmap"]."\n";
  }
  $name=$this->getValue("GRP_NAME");
  if ($name=="") $this->setValue("GRP_NAME",$this->getValue("US_LOGIN"));
  $err=$this->modify();
  

  $user=$this->getWUser();
  if ($user) {
    if ($user->isgroup=='Y') {
      $user->firstname="";
      $user->lastname=$this->getValue("grp_name");    
      $user->mail=$this->getValue("grp_mail");
    } else {  
      $user->firstname=$this->getValue("us_fname");
      $user->lastname=$this->getValue("us_lname");
      $user->mail=$this->getValue("us_mail");
    }
    $user->modify(true);
  }

  // insert in groups
  $dnmembers=$info["memberof"];
  if ($dnmembers) {
    if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
    foreach ($dnmembers as $k=>$dnmember) {
      $err=$this->getADDN($dnmember,$infogrp);
      $gid=$infogrp["objectsid"];
      $err=createADGroup($gid,$dg);      
      if ($err=="") {
	$err=$dg->addFile($this->initid);
      }
    }
  }
  

  $dnmembers=$info["primarygroupid"];
  if ($dnmembers) {// for user/group Active Directory
    if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
    
    foreach ($dnmembers as $k=>$pgid) {
      //      print "<p>Find2 Primary group:$dnmember</p>";
      $basesid=substr($info["objectsid"],0,strrpos($info["objectsid"],"-"));
      $gid=$basesid."-".$pgid;
      $err=createADGroup($gid,$dg);    
      if ($err=="") {
	$err=$dg->addFile($this->initid);
      }
    }
  }


  if ($this->doctype != 'D') { // for user posixAccount
    $gid=$info["gidnumber"];
    if ($gid) {
      $err=createADGroup($gid,$dg);    
      if ($err=="") {
	$err=$dg->addFile($this->initid);
      }      
    }
  } else {
    // for group posixGroup
    
    $dnmembers=$info["memberuid"];
    if ($dnmembers) {// for user/group Active Directory
      if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
      
      foreach ($dnmembers as $k=>$gid) {
	//	print "<p>Find Membeers UIds group:$gid</p>";
	$docu=getDocFromUniqId($gid);
	if ($docu) {
	  $err=$this->addFile($docu->initid);
	}
      }
    }
  }

   
  return $err;
}







/**
 * return LDAP AD information from DN for a group only
 * @param string $dn distinguish name
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
 function getADDN($dn,&$info) {
   include_once("NU/Lib.NU.php");
  $ldaphost=getParam("NU_LDAP_HOST");
  $ldapbase=getParam("NU_LDAP_BASE");
  $ldappw=getParam("NU_LDAP_PASSWORD");
  $ldapbinddn=getParam("NU_LDAP_BINDDN");

  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    $filter="objectclass=*";
    $sr=ldap_read($ds, $dn,$filter);
    $count= ldap_count_entries($ds, $sr);
    if ($count==1) {
      $info1 = ldap_get_entries($ds, $sr);
      $info0=$info1[0];
      $entry= ldap_first_entry($ds, $sr);

      foreach ($info0 as $k=>$v) {
	if (! is_numeric($k)) {
	  if ($k=="objectsid") {
	    // get binary value from ldap and decode it
	    $values = ldap_get_values_len($ds, $entry,$k);	   
	    $info[$k]=sid_decode($values[0]);
	  } else { 
	    if ($v["count"]==1)  $info[$k]=$v[0];
	    else {
	      //	    unset($v["count"]);
	      if (is_array($v))  unset($v["count"]);   
	      $info[$k]=$v;
	    }
	  }
	}
      }      
    } else {
      if ($count==0) $err=sprintf(_("Cannot find group [%s]"),$login);
      else $err=sprintf(_("Find mutiple grp with same login  [%s]"),$login);
    }

    
    ldap_close($ds);

  } else {
    $err=sprintf(_("Unable to connect to LDAP server %s"),$ldaphost);
  }

  return $err;
  
}


/**
 * return Active Directory identificator from SID
 * @param string $sid ascii sid
 * @return string the identificator (last number of sid)
 */
function getADId($sid) {
  return substr(strrchr($sid, "-"), 1);
}
?>