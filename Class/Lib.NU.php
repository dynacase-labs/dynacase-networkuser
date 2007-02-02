<?php
/**
 *  LDAP functions
 *
 * @author Anakeen 2007
 * @version $Id: Lib.NU.php,v 1.6 2007/02/02 13:56:40 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 */
 /**
 */

include_once("AD/Lib.ConfLDAP.php");
/**
 * return LDAP AD information from SID
 * @param string $sid ascii unique id
 * @param string $ldapuniqid ldap attribute for filter unique id
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getAdInfoFromSid($sid,&$info,$isgroup) {

  $ldapuniqid=strtolower(getLDAPconf(getParam("NU_LDAP_KIND"),
				     ($isgroup)?"LDAP_GROUPUID":"LDAP_USERUID"));
  if ($ldapuniqid == "objectsid") {
    $hex='\\'.substr(strtoupper(chunk_split(bin2hex(sid_encode($sid)),2,'\\')),0,-1);
    $sid=$hex;
  }
  $err=getLDAPFromUid($sid,$isgroup,$info);
  return $err;  
}
/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getLDAPFrom($login,$ldapclass,$ldapbindloginattribute,&$info) {
  include_once("AD/Lib.AD.php");
  $ldaphost=getParam("NU_LDAP_HOST");
  $ldapbase=getParam("NU_LDAP_BASE");
  $ldappw=getParam("NU_LDAP_PASSWORD");
  $ldapbinddn=getParam("NU_LDAP_BINDDN");


  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    $filter=sprintf("(&(objectClass=%s)(%s=%s))",
		    $ldapclass,$ldapbindloginattribute,$login);
    $sr=ldap_search($ds, $ldapbase, $filter); 
    $count= ldap_count_entries($ds, $sr);

    //print "ldap_search($ds, $ldapbase, $filter\n"; print "found:$count\n";
    if ($count==1) {
      $info1 = ldap_get_entries($ds, $sr);
      $info0= $info1[0];
      $entry= ldap_first_entry($ds, $sr);
      //      print "<pre>";print_r($info);print "</pre>";
      foreach ($info0 as $k=>$v) {
	if (! is_numeric($k)) {
	  //print "$k:[".print_r2(ldap_get_values($ds, $entry, $k))."]";
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
      if ($count==0) $err=sprintf(_("Cannot find user [%s]"),$login);
      else $err=sprintf(_("Find mutiple user with same id  [%s]"),$login);
    }

    
    ldap_close($ds);

  } else {
    $err=sprintf(_("Unable to connect to LDAP server %s"),$ldaphost);
  }

  return $err;
  
}
/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getLDAPFromLogin($login,$isgroup,&$info) {
  $conf=getLDAPconf(getParam("NU_LDAP_KIND"));
  if ($isgroup) {
    $ldapattr=$conf["LDAP_GROUPLOGIN"];
    $ldapclass=$conf["LDAP_GROUPCLASS"];
  } else {
    $ldapattr=$conf["LDAP_USERLOGIN"];
    $ldapclass=$conf["LDAP_USERCLASS"];
  }
  return getLDAPFrom($login,$ldapclass,$ldapattr,$info);
  
}
/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getLDAPFromUid($uid,$isgroup,&$info) {
  $conf=getLDAPconf(getParam("NU_LDAP_KIND"));
  if ($isgroup) {
    $ldapattr=$conf["LDAP_GROUPUID"];
    $ldapclass=$conf["LDAP_GROUPCLASS"];
  } else {
    $ldapattr=$conf["LDAP_USERUID"];
    $ldapclass=$conf["LDAP_USERCLASS"];
  }
  return getLDAPFrom($uid,$ldapclass,$ldapattr,$info);
  
}
/**
 * encode Active Directory session id in binary format
 * @param string $sid
 * @return data the binary id
 */
function sid_encode($sid) {
  $osid=false;
  if (!$sid) return false;
  $n232=pow(2,32);
  $tid=explode('-',$sid);
  
  $number=count($tid)-3;
  $tpack["rev"]=sprintf("%02d",intval($tid[1]));
  $tpack["b"]=sprintf("%02d",$number); // 
  if (floatval($tid[2]) >= $n232) {    
    $tpack["c"]=intval(floatval($tid[2])/$n232);
    $tpack["d"]=intval(floatval($tid[2])-floatval($tpack["c"])*$n232);
  } else {
    $tpack["c"]=0;
    $tpack["d"]=$tid[2];
  }
  for ($i=0;$i<$number;$i++) {    
    $tpack["e".($i+1)]=floatval($tid[$i+3]);
  }

  if ($number==5) 
  $osid=pack("H2H2nNV*",$tpack["rev"],$tpack["b"],$tpack["c"],$tpack["d"],
	  $tpack["e1"],$tpack["e2"],$tpack["e3"],$tpack["e4"],$tpack["e5"] );

  if ($number==2) 
    $osid=pack("H2H2nNV*",$tpack["rev"],$tpack["b"],$tpack["c"],$tpack["d"],
	       $tpack["e1"],$tpack["e2"] );
  return $osid;
}

/**
 * Decode Active Directory session id in ascii format
 * @param data $osid the binary session id
 * @return string the ascii id (false if error)
 */
function sid_decode($osid) {
  $sid=false;
  if (!$osid) return false;
  $u=unpack("H2rev/H2b/nc/Nd/V*e", $osid);
  if ($u) {
    $n232=pow(2,32);
    unset($u["b"]);
    $u["c"]= $n232*$u["c"]+$u["d"];
    unset($u["d"]);

    $sid="S";
    foreach ($u as $v) {
      if ($v < 0) $v=$n232 + $v;
      $sid.= "-".$v;
    }
  }
  return $sid;
}
?>

