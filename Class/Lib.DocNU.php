<?php
/**
 *  LDAP Document methods
 *
 * @author Anakeen 2007
 * @version $Id: Lib.DocNU.php,v 1.10 2007/03/06 16:29:36 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 */
 /**
 */

include_once("FDL/Class.Doc.php");
include_once("FDL/Lib.Dir.php");
include_once("NU/Lib.NU.php");

/**
 * return document referenced by Active Directory sid or OpenLDAP uid
 * @param string $sid ascii sid
 * @return Doc document object or false if not found
 */
function getDocFromUniqId($sid) {

  $dbaccess=getParam("FREEDOM_DB");
  $filter=array("ldap_uniqid='".pg_escape_string($sid)."'");
  $ls = getChildDoc($dbaccess, 0 ,0,1, $filter, 1, "LIST","LDAPGROUP");
  if (count($ls) > 0) return $ls[0];
  $ls = getChildDoc($dbaccess, 0 ,0,1, $filter, 1, "LIST","LDAPUSER");
  if (count($ls) > 0) return $ls[0];


  return false;  
}
    
function createLDAPFamily($sid,&$doc,$family,$isgroup) {
  $err=getAdInfoFromSid($sid,$infogrp,$isgroup);
 
  if ($err=="") {
    $g=new User("");
    $alogin=strtolower(getLDAPconf(getParam("NU_LDAP_KIND"),
				   ($isgroup)?"LDAP_GROUPLOGIN":"LDAP_USERLOGIN"));
  
    if (seems_utf8($infogrp[$alogin])) $infogrp[$alogin]=utf8_decode($infogrp[$alogin]);
    $g->SetLoginName($infogrp[$alogin]);
    if (! $g->isAffected()) {
      foreach ($infogrp as $k=>$v)  if (seems_utf8($v)) $infogrp[$k]=utf8_decode($v);

      $g->firstname=($infogrp["givenname"]=="")?$infogrp["cn"]:$infogrp["givenname"];
      $g->lastname=$infogrp["sn"];
      $g->login=$infogrp[$alogin];

      $g->isgroup=($isgroup)?'Y':'N';
      $g->password_new=uniqid("ad");
      $g->iddomain="0";
      $g->famid=$family;
      $err=$g->Add(); 
    }
    if ($err=="") {
      $gfid=$g->fid;
      $dbaccess=getParam("FREEDOM_DB");
      $doc=new_doc($dbaccess,$gfid);
      $doc->refreshFromLDAP();
    }
  }
  if ($err) return sprintf(_("Cannot create LDAP %s [%s] : %s"),
			   $family,$sid,$err);
}

function createLDAPGroup($sid,&$doc) {
  if (!$sid) return false;
  $err=createLDAPFamily($sid,$doc,"LDAPGROUP",true);
  return $err;
}

function createLDAPUser($sid,&$doc) { 
  if (!$sid) return false;
  $err=createLDAPFamily($sid,$doc,"LDAPUSER",false);
  return $err;
}

?>