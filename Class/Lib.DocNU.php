<?php

include_once("FDL/Class.Doc.php");
include_once("FDL/Lib.Dir.php");

/**
 * return document referenced by Active Directory sid or OpenLDAP uid
 * @param string $sid ascii sid
 * @return Doc document object or false if not found
 */
function getDocFromUniqId($sid) {

  $dbaccess=getParam("FREEDOM_DB");
  $filter=array("ldap_uniqid='".pg_escape_string($sid)."'");
  $ls = getChildDoc($dbaccess, 0 ,0,1, $filter, 1, "LIST","LDAPGROUP");
  if (count($ls) == 1) return $ls[0];
  $ls = getChildDoc($dbaccess, 0 ,0,1, $filter, 1, "LIST","LDAPUSER");
  if (count($ls) == 1) return $ls[0];


  return false;  
}
    
function createADFamily($sid,&$doc,$family,$isgroup) {
  $err=getAdInfoFromSid($sid,$infogrp);
  if ($err=="") {
  $g=new User("");
  $alogin=strtolower(getParam("LDAP_LOGIN"));
  
  $g->SetLoginName($infogrp[$alogin]);
  if (! $g->isAffected()) {
    
    $g->firstname="";
    $g->lastname=$infogrp["name"];
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
    $doc->refreshFromAD();
  }
  }
  if ($err) return sprintf(_("cannot create LDAP %s [%s] : %s"),
			   $family,$sid,$err);
}

function createADGroup($sid,&$doc) {
  if (!$sid) return false;
  $err=createADFamily($sid,$doc,"LDAPGROUP",true);
  return $err;
}

function createADUser($sid,&$doc) { 
  if (!$sid) return false;
  $err=createADFamily($sid,$doc,"LDAPUSER",false);
  return $err;
}

?>