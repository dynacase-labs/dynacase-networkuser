<?php

include_once("FDL/Class.Doc.php");
include_once("FDL/Lib.Dir.php");

/**
 * return document referenced by Active Directory sid
 * @param string $sid ascii sid
 * @return Doc document object or false if not found
 */
function getDocFromSid($sid) {

  $dbaccess=getParam("FREEDOM_DB");
  $filter=array("ad_sid='".pg_escape_string($sid)."'");
  $ls = getChildDoc($dbaccess, 0 ,0,1, $filter, 1, "LIST","ADGROUP");

  if (count($ls) == 1) return $ls[0];
  return false;  
}
    
function createADFamily($sid,&$doc,$family,$isgroup) {
  $err=getAdInfoFromSid($sid,$infogrp);
  $g=new User("");

  $g->SetLoginName($infogrp["samaccountname"]);
  if (! $g->isAffected()) {
    
    $g->firstname="";
    $g->lastname=$infogrp["name"];
    $g->login=$infogrp["samaccountname"];

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
  if ($err) return sprintf(_("cannot create active directory group [%s] : %s"),
			   $sid,$err);
}

function createADGroup($sid,&$doc) {
  createADFamily($sid,$doc,"ADGROUP",true);
}

function createADUser($sid,&$doc) { 
  createADFamily($sid,$doc,"ADUSER",false);
}

?>