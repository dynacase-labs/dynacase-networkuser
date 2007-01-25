<?php
/**
 * Active Directory Group manipulation
 *
 * @author Anakeen 2007
 * @version $Id: Method.NU.php,v 1.1 2007/01/25 14:33:46 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 */
 /**
 */



function refreshFromAD() {
  $err=$this->getADUser($this->getValue('us_login'),$info);
  //  print_r2($info);
  //var_dump (xdebug_get_function_stack());		 

  $ldapmap=$this->getMapAttributes();
  // print_r2($ldapmap);
  foreach ($ldapmap as $k=>$v) {
    if ($v["ldapname"] && $v["ldapmap"] && ($v["ldapmap"][0]!=':') && ($info[strtolower($v["ldapname"])])) {
      $val=$info[strtolower($v["ldapname"])];
      $att=$v["ldapmap"];
      $this->setValue($att,$val);
      //print "$att:[$val]<br>";
    }
  }
  $this->modify();

  $dnmembers=$info["memberof"];
  if ($dnmembers) {
    if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
    foreach ($dnmembers as $k=>$dnmember) {
      print "<p>Find $dnmember</p>";
      $err=$this->getADDN($dnmember,$infogrp);
      $g=new User("");
      $g->SetLoginName($infogrp["samaccountname"]);
      if (! $g->isAffected()) {
	print "<H1>Need create group ".$infogrp["samaccountname"]."</h1>";

    
	$g->firstname="";
	$g->lastname=$infogrp["name"];
	$g->login=$infogrp["samaccountname"];
	$g->isgroup='Y';
	$g->password_new=uniqid("ad");
	$g->iddomain="0";
	$g->famid="ADGROUP";
	$err=$g->Add();
	print "$err: create groupe".$g->fid;
      }
      if ($err=="") {
	$gfid=$g->fid;
	$dg=new_doc($this->dbaccess,$gfid);
	$err=$dg->addFile($this->initid);
	$dg->refreshFromAD();
      }
    }
  }


  $dnmembers=$info["primarygroupid"];
  if ($dnmembers) {
    if (! is_array($dnmembers)) $dnmembers=array($dnmembers);
    
    foreach ($dnmembers as $k=>$pgid) {
      print "<p>Find2 Primary group:$dnmember</p>";
      $basesid=substr($info["objectsid"],0,strrpos($info["objectsid"],"-"));
      $gid=$basesid."-".$pgid;
      print "<p>Search $gid</p>";
      $hex='\\\\'.substr(strtoupper(chunk_split(bin2hex($this->sid_encode($gid)),2,'\\\\')),0,-1);
      print "[$hex]";
      $err=$this->getADUser($hex,$infogrp,"objectsid");
      $g=new User("");
      print_r2($infogrp);
      $g->SetLoginName($infogrp["samaccountname"]);
      if (! $g->isAffected()) {
	print "<H1>Need create group ".$infogrp["samaccountname"]."</h1>";

    
	$g->firstname="";
	$g->lastname=$infogrp["name"];
	$g->login=$infogrp["samaccountname"];
	$g->isgroup='Y';
	$g->password_new=uniqid("ad");
	$g->iddomain="0";
	$g->famid="ADGROUP";
	$err=$g->Add();
	print "$err: create groupe".$g->fid;
      }
      if ($err=="") {
	$gfid=$g->fid;
	$dg=new_doc($this->dbaccess,$gfid);
	$err=$dg->addFile($this->initid);
	$dg->refreshFromAD();
      }
    }
  }

  return $err;
}

function sid_decode($osid) {
  $sid=false;
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
function sid_encode($sid) {
  $osid=false;

  $n232=pow(2,32);
  $tid=explode('-',$sid);
 
  $tpack["zrev"]=sprintf("%02d",intval($tid[1]));
  $tpack["b"]=sprintf("%02d",5); // always 5
  if (floatval($tid[2]) >= $n232) {    
    $tpack["c"]=intval(floatval($tid[2])/$n232);
    $tpack["d"]=intval(floatval($tid[2])-floatval($tpack["c"])*$n232);
  } else {
    $tpack["c"]=0;
    $tpack["d"]=$tid[2];
  }
  $tpack["e1"]=floatval($tid[3]);
  $tpack["e2"]=floatval($tid[4]);
  $tpack["e3"]=floatval($tid[5]);
  $tpack["e4"]=floatval($tid[6]);
  $tpack["e5"]=floatval($tid[7]);

  $osid=pack("H2H2nNV*",$tpack["zrev"],$tpack["b"],$tpack["c"],$tpack["d"],
	  $tpack["e1"],$tpack["e2"],$tpack["e3"],$tpack["e4"],$tpack["e5"] );

  return $osid;
}


/**
 * return LDAP AD information from the $login
 * @param string $login connection identificator
 * @param array &$info ldap information
 * @return string error message - empty means no error
 */
function getADUser($login,&$info,$ldapbindloginattribute="sAMAccountName") {
  $ldaphost="ad.tlse.i-cesam.com";
  $ldapbase="dc=ad,dc=tlse,dc=i-cesam,dc=com";
  $ldappw="anakeen";
  $ldapbinddn="cn=administrateur,cn=users,dc=ad,dc=tlse,dc=i-cesam,dc=com";


  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    $sr=ldap_search($ds, "$ldapbase", "$ldapbindloginattribute=$login"); 

    $count= ldap_count_entries($ds, $sr);
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
	    $info[$k]=$this->sid_decode($values[0]);
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
      else $err=sprintf(_("Find mutiple user with same login  [%s]"),$login);
    }

    
    ldap_close($ds);

  } else {
    $err=sprintf(_("Unable to connect to LDAP server %s"),$ldaphost);
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
  $ldaphost="ad.tlse.i-cesam.com";
  $ldapbase="dc=ad,dc=tlse,dc=i-cesam,dc=com";
  $ldappw="anakeen";
  $ldapbinddn="cn=administrateur,cn=users,dc=ad,dc=tlse,dc=i-cesam,dc=com";
  $ldapbindloginattribute="dn";

  $info=array();

  $ds=ldap_connect($ldaphost);  // must be a valid LDAP server!

  if ($ds) {
    $r=ldap_bind($ds,$ldapbinddn,$ldappw);  

    // Search login entry
    //$sr=ldap_search($ds, "$ldapbase", "$ldapbindloginattribute=$dn"); 
    $filter="(objectclass=group)";
    $sr=ldap_read($ds, $dn,$filter);
    $count= ldap_count_entries($ds, $sr);
    if ($count==1) {
      $info1 = ldap_get_entries($ds, $sr);
      $info0=$info1[0];
      $entry= ldap_first_entry($ds, $sr);
      //      print "<pre>";print_r($info);print "</pre>";
      foreach ($info0 as $k=>$v) {
	if (! is_numeric($k)) {
	  if ($k=="objectsid") {
	    // get binary value from ldap and decode it
	    $values = ldap_get_values_len($ds, $entry,$k);	   
	    $info[$k]=$this->sid_decode($values[0]);
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



function getADId($sid) {
  return substr(strrchr($sid, "-"), 1);
}
?>