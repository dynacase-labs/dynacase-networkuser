<?php
/**
 *  LDAP Document methods
 *
 * @author Anakeen 2007
 * @version $Id: Lib.DocNU.php,v 1.11 2007/10/08 13:00:51 eric Exp $
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
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
  
    if (! seems_utf8($infogrp[$alogin])) $infogrp[$alogin]=utf8_encode($infogrp[$alogin]);
    $g->SetLoginName($infogrp[$alogin]);
    if (! $g->isAffected()) {
      foreach ($infogrp as $k=>$v) {
        if( is_scalar($v) && ! seems_utf8($v) ) $infogrp[$k]=utf8_encode($v);
      }

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
      if ($gfid) {
	$dbaccess=getParam("FREEDOM_DB");
	$doc=new_doc($dbaccess,$gfid);
	if( $doc->isAlive() && method_exists($doc, 'refreshFromLDAP') ) $doc->refreshFromLDAP();
      }
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