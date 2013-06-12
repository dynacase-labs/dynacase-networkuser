<?php
/*
 *  LDAP Document methods
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
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
        $search->addFilter("ldap_uniqid='%s'", $sid);
        $search->search();
        return $search->getNextDoc();
    };

    if ($famId != '') {
        $ls = $searchElement($famId);
        if (is_object($ls)) {
            return $ls;
        }
    } else {
        $ls = $searchElement("LDAPGROUP");
         if (is_object($ls)) {
            return $ls;
        }
        $ls = $searchElement("LDAPUSER");
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
        $g->SetLoginName($infogrp[$alogin]);
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
                $dbaccess = getParam("FREEDOM_DB");
                $doc = new_doc($dbaccess, $gfid);
                if ($doc->isAlive() && method_exists($doc, 'refreshFromLDAP')) {
                    /* @var $doc _NU_COMMON */
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
 * @param _LDAPGROUP $doc
 * @return bool|string
 */
function createLDAPGroup($sid, &$doc)
{
    if (!$sid) return false;
    $err = createLDAPFamily($sid, $doc, "LDAPGROUP", true);
    return $err;
}

/**
 * @param string $sid identifier
 * @param _LDAPUSER $doc
 * @return bool|string
 */
function createLDAPUser($sid, &$doc)
{
    if (!$sid) return false;
    $err = createLDAPFamily($sid, $doc, "LDAPUSER", false);
    return $err;
}
