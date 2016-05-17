<?php
/*
 *  LDAP Document methods
 *
 * @author Anakeen
 * @package NU
*/

include_once ("FDL/Class.Doc.php");
include_once ("FDL/Lib.Dir.php");
include_once ("NU/Lib.NU.php");
/**
 * return document referenced by Active Directory sid or OpenLDAP uid
 * @param string $sid ascii sid
 * @param string $famId
 * @return Doc document object or false if not found
 */
function getDocFromUniqId($sid, $famId = "")
{
    $searchElement = function ($famId) use ($sid)
    {
        $search = new SearchDoc("", $famId);
        $search->setObjectReturn(true);
        $search->setSlice(1);
        $search->addFilter("%s = '%s'", \Dcp\AttributeIdentifiers\Ldapuser::ldap_uniqid, $sid);
        $search->search();
        return $search->getNextDoc();
    };
    
    if ($famId != '') {
        $ls = $searchElement($famId);
        if (is_object($ls)) {
            return $ls;
        }
    } else {
        $ls = $searchElement(\Dcp\Family\Ldapgroup::familyName);
        if (is_object($ls)) {
            return $ls;
        }
        $ls = $searchElement(\Dcp\Family\Ldapuser::familyName);
        if (is_object($ls)) {
            return $ls;
        }
    }
    
    return false;
}

function createLDAPFamily($sid, &$doc, $family, $isgroup)
{
    $err = getAdInfoFromSid($sid, $infogrp, $isgroup);
    
    if ($err == "") {
        $g = new Account("");
        $alogin = strtolower(getLDAPconf(getParam("NU_LDAP_KIND") , ($isgroup) ? "LDAP_GROUPLOGIN" : "LDAP_USERLOGIN"));
        
        if (!seems_utf8($infogrp[$alogin])) {
            $infogrp[$alogin] = utf8_encode($infogrp[$alogin]);
        }
        $g->setLoginName($infogrp[$alogin]);
        if (!$g->isAffected()) {
            foreach ($infogrp as $k => $v) {
                if (is_scalar($v) && !seems_utf8($v)) {
                    $infogrp[$k] = utf8_encode($v);
                }
            }
            
            $g->firstname = ($infogrp["givenname"] == "") ? $infogrp["cn"] : $infogrp["givenname"];
            $g->lastname = $infogrp["sn"];
            $g->login = $infogrp[$alogin];
            
            $g->accounttype = ($isgroup) ? 'G' : 'U';
            $g->password_new = uniqid("ad");
            $g->famid = $family;
            $err = $g->Add();
        }
        if ($err == "") {
            $gfid = $g->fid;
            if ($gfid) {
                $doc = new_Doc('', $gfid);
                if ($doc->isAlive() && method_exists($doc, 'refreshFromLDAP')) {
                    /* @var \Dcp\Networkuser\NUCommon $doc */
                    $doc->refreshFromLDAP();
                }
            }
        }
    }
    if ($err) {
        return sprintf(_("Cannot create LDAP %s [%s] : %s") , $family, $sid, $err);
    }
    return "";
}
/**
 * @param string $sid identifier
 * @param \Dcp\Networkuser\Ldapgroup $doc
 * @return bool|string
 */
function createLDAPGroup($sid, &$doc)
{
    if (!$sid) return false;
    $err = createLDAPFamily($sid, $doc, \Dcp\Family\Ldapgroup::familyName, true);
    return $err;
}
/**
 * @param string $sid identifier
 * @param \Dcp\Networkuser\NUCommon $doc
 * @return bool|string
 */
function createLDAPUser($sid, &$doc)
{
    if (!$sid) return false;
    $err = createLDAPFamily($sid, $doc, \Dcp\Family\Ldapuser::familyName, false);
    return $err;
}
