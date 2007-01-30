<?php
/**
 * Active Directory Group manipulation
 *
 * @author Anakeen 2007
 * @version $Id: Method.NU.php,v 1.4 2007/01/30 17:12:00 eric Exp $
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
  include_once("AD/Lib.AD.php");
  include_once("AD/Lib.DocAD.php");
  $err=getADUser($this->getValue('us_login'),$info);
  //    print_r($info);
  //var_dump (xdebug_get_function_stack());		 

  $ldapmap=$this->getMapAttributes();
  // print_r2($ldapmap);
  foreach ($ldapmap as $k=>$v) {
    if ($v["ldapname"] && $v["ldapmap"] && ($v["ldapmap"][0]!=':') && ($info[strtolower($v["ldapname"])])) {
      $val=$info[strtolower($v["ldapname"])];
      $att=$v["ldapmap"];
      if ($val)     $this->setValue($att,$val);

    }
  }
  $this->modify();

  $dnmembers=$info["memberof"];
  if ($dnmembers) {
    if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
    foreach ($dnmembers as $k=>$dnmember) {
      //      print "<p>Find $dnmember</p>";
      $err=$this->getADDN($dnmember,$infogrp);
      $gid=$infogrp["objectsid"];
      $err=createADGroup($gid,$dg);      
      if ($err=="") {
	$err=$dg->addFile($this->initid);
      }
    }
  }


  $dnmembers=$info["primarygroupid"];
  if ($dnmembers) {
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

  return $err;
}







/**
 * return LDAP AD information from DN for a group only
 * @param string $dn distinguish name
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
 function getADDN($dn,&$info) {
   include_once("AD/Lib.AD.php");
  $ldaphost=getParam("AD_HOST");
  $ldapbase=getParam("AD_BASE");
  $ldappw=getParam("AD_PASSWORD");
  $ldapbinddn=getParam("AD_BINDDN");

  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    $filter="(objectclass=group)";
    $filter="(objectclass=posixGroup)";
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