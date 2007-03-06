<?php
/**
 * Import Users andgrops from a Active Directory
 *
 * @author Anakeen 2007
 * @version $Id: nu_importldap.php,v 1.11 2007/03/06 16:29:36 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 * @subpackage 
 */
 /**
 */

// refreah for a classname
// use this only if you have changed title attributes

include_once("FDL/Lib.Attr.php");
include_once("FDL/Class.DocFam.php");
include_once("NU/Lib.DocNU.php");


define("SKIPCOLOR",'[1;31;40m');
define("UPDTCOLOR",'[1;32;40m');
define("STOPCOLOR",'[0m');

$dbaccess=$appl->GetParam("FREEDOM_DB");
if ($dbaccess == "") {
  print "Freedom Database not found : param FREEDOM_DB\n";
  exit;
}

$conf=getLDAPconf(getParam("NU_LDAP_KIND"));
if (! $conf) {
  print "Kind of LDAP database must be defined: parameter NU_LDAP_KIND.\n";
  exit;
  
 }

/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function searchinLDAP($filter,$ldapuniqid,&$info) {
  $ldaphost=getParam("NU_LDAP_HOST");
  $ldapbase=getParam("NU_LDAP_BASE");
  $ldappw=getParam("NU_LDAP_PASSWORD");
  $ldapbinddn=getParam("NU_LDAP_BINDDN");
  $ldapuniqid=strtolower($ldapuniqid);

  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  
    if ($r) {
      // Search login entry
      $sr=ldap_search($ds, "$ldapbase", $filter); 

      $count= ldap_count_entries($ds, $sr);
   
      $infos = ldap_get_entries($ds, $sr);
      $entry= ldap_first_entry($ds, $sr);

      foreach ($infos as $info0) {
	$sid=false;
	if (! is_array($info0)) continue;
	$info1=array();
	foreach ($info0 as $k=>$v) {
	  if (! is_numeric($k)) {
	    //print "$k:[".print_r2(ldap_get_values($ds, $entry, $k))."]";
	    if ($k=="objectsid") {
	      // get binary value from ldap and decode it
	      $values = ldap_get_values_len($ds, $entry,$k);	   
	      $info1[$k]=sid_decode($values[0]);
	    
	    } else {
	      if ($v["count"]==1)  $info1[$k]=$v[0];
	      else {
		//	    unset($v["count"]);
		if (is_array($v))  unset($v["count"]);   
		$info1[$k]=$v;
	      }
	    }
	    if ($k==$ldapuniqid) $sid=$info1[$k];
	  }
	}
	if ($sid)   $info[$sid]=$info1;
	else $info[]=$info1;
      
	$entry= ldap_next_entry($ds, $entry);
      }

    } else $err=sprintf(_("Unable to bind to LDAP server %s"),$ldaphost);
    ldap_close($ds);

  } else {
    $err=sprintf(_("Unable to connect to LDAP server %s"),$ldaphost);
  }

  return $err;
  
}

//$err=searchinLDAP("objectclass=group",$groups);
$err=searchinLDAP("objectclass=".$conf["LDAP_GROUPCLASS"],$conf["LDAP_GROUPUID"],$groups);
if ($err) print "ERROR:$err\n";
//print_r(array_keys($groups));
//print_r(($groups));

foreach ($groups as $sid=>$group) {
  print "Search group $sid...";
  $doc=getDocFromUniqId($sid);

  if (! $doc) {
    $err=createLDAPGroup($sid,$doc);
    if ($err!="") print SKIPCOLOR;
    print "Create Group ".$doc->title;
    if ($err!="") print "[$err]".STOPCOLOR;
    print "\n";
  } else  {
    $err=$doc->refreshFromLDAP();
    if ($err=="") $doc->postModify();
    if ($err!="") print SKIPCOLOR;
    print "Refresh Group ".$doc->id.$doc->title;
    if ($err!="") print "[$err]".STOPCOLOR;
    print "\n";
  }
}

//$err=searchinLDAP("objectclass=user",$users);
$err=searchinLDAP("objectclass=".$conf["LDAP_USERCLASS"],$conf["LDAP_USERUID"],$users);
//print_r(($users));
foreach ($users as $sid=>$user) {
  print "Search user $sid...";
  $doc=getDocFromUniqId($sid);
  if (! $doc) {
    $err=createLDAPUser($sid,$doc);   
    if ($err!="") print SKIPCOLOR; 
    print "Create User ".$doc->title;
    if ($err!="") print "[$err]".STOPCOLOR;
    print "\n";
  } else  {
    $err=$doc->refreshFromLDAP();
    if ($err=="") $doc->postModify();
    if ($err!="") print SKIPCOLOR; 
    print "Refresh ".$doc->title;
    if ($err!="") print "[$err]".STOPCOLOR;
    print "\n";
  }
}

?>