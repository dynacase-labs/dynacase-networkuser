<?php
/*
 * Active Directory Group manipulation
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/
/* @begin-method-ignore */
class _NU_COMMON extends _IGROUP
{
    public function existsLogin($a, $b)
    {
        // stub
        return '';
    }
    /* @end-method-ignore */
    /**
     * Not write in Dynacase Ldap
     */
    function UseLdap()
    {
        return false;
    }
    /**
     * @apiExpose
     * @return bool|string
     */
    function refreshFromLDAP()
    {
        include_once "FDL/Lib.Usercard.php";
        include_once "NU/Lib.NU.php";
        include_once "NU/Lib.DocNU.php";
        
        $ldap_group_base_dn = getParam("NU_LDAP_GROUP_BASE_DN", "");
        
        $err = getLDAPFromLogin($this->getRawValue('us_login') , ($this->doctype == 'D') , $info);
        $ldapmap = $this->getMapAttributes();
        foreach ($ldapmap as $v) {
            
            $ldapName = strtolower($v["ldapname"]);
            
            if ($ldapName && ($ldapName[0] != ':') && !empty($info[$ldapName])) {
                if ($v['ldapclass'] != 'top') {
                    if (is_array($info['objectclass']) && !in_array($v['ldapclass'], $info['objectclass'])) {
                        continue;
                    } else if (is_string($info['objectclass']) && $v['ldapclass'] != $info['objectclass']) {
                        continue;
                    }
                }
                $val = $info[$ldapName];
                $att = $v["ldapmap"];
                if ($val) {
                    if ((!is_array($val)) && !seems_utf8($val)) $val = utf8_encode($val);
                    $err.= $this->setValue($att, $val);
                }
            }
        }
        $name = $this->getRawValue("GRP_NAME");
        if ($name == "") $this->setValue("GRP_NAME", $this->getRawValue("US_LOGIN"));
        $err = $this->modify();
        
        $t_docgroupid = $this->getMultipleRawValues("us_idgroup"); // memo group of the user
        $tnew_docgroupid = array();
        
        $user = $this->getAccount();
        $userMailHasChanged = false;
        if ($user) {
            if ($user->accounttype == 'G') {
                $user->firstname = "";
                $user->lastname = $this->getRawValue("grp_name");
                $user->mail = $this->getRawValue("grp_mail");
            } else {
                $user->firstname = $this->getRawValue("us_fname");
                $user->lastname = $this->getRawValue("us_lname");
                $this->setValue("us_mail", $this->getRawValue("us_extmail"));
                $user->mail = $this->getRawValue("us_mail");
                if ($this->getOldRawValue('us_mail') != '') {
                    $userMailHasChanged = true;
                }
            }
            $user->modify(true);
        }
        $dg = null;
        /*
         * insert in LDAP/AD groups if group base dn is defined
        */
        if ($ldap_group_base_dn != '') {
            
            $dnmembers = isset($info["memberof"]) ? $info["memberof"] : "";
            if ($dnmembers) {
                if (!is_array($dnmembers)) {
                    $dnmembers = array(
                        $dnmembers
                    );
                }
                foreach ($dnmembers as $dnmember) {
                    $err = $this->getADDN($dnmember, $infogrp);
                    if ($err == "") {
                        $gid = $infogrp["objectsid"];
                        $err = createLDAPGroup($gid, $dg);
                        if ($err == "") {
                            if (is_object($dg)) {
                                $err = $dg->insertDocument($this->initid);
                                $tnew_docgroupid[] = $dg->initid;
                                if ((!in_array($dg->initid, $t_docgroupid)) && ($err == "")) {
                                    $this->addHistoryEntry(sprintf(_("Add to group %s") , $dg->title));
                                }
                            }
                        }
                    }
                }
            }
            
            $dnmembers = isset($info["primarygroupid"]) ? $info["primarygroupid"] : "";
            if ($dnmembers) { // for user/group Active Directory
                if (!is_array($dnmembers)) $dnmembers = array(
                    $dnmembers
                );
                
                foreach ($dnmembers as $pgid) {
                    $basesid = substr($info["objectsid"], 0, strrpos($info["objectsid"], "-"));
                    $gid = $basesid . "-" . $pgid;
                    $err = createLDAPGroup($gid, $dg);
                    if ($err == "") {
                        $err = $dg->insertDocument($this->initid);
                        $tnew_docgroupid[] = $dg->initid;
                        if ((!in_array($dg->initid, $t_docgroupid)) && ($err == "")) {
                            $this->addHistoryEntry(sprintf(_("Add to group %s") , $dg->title));
                        }
                    }
                }
            }
            
            if ($this->doctype != 'D') { // for user posixAccount
                $gid = isset($info["gidnumber"]) ? $info["gidnumber"] : "";
                if ($gid) {
                    $err = createLDAPGroup($gid, $dg);
                    if ($err == "") {
                        $err = $dg->insertDocument($this->initid);
                        $tnew_docgroupid[] = $dg->initid;
                        if ((!in_array($dg->initid, $t_docgroupid)) && ($err == "")) {
                            $this->addHistoryEntry(sprintf(_("Add to group %s") , $dg->title));
                        }
                    }
                }
            } else {
                // for group posixGroup
                $dnmembers = isset($info["memberuid"]) ? $info["memberuid"] : "";
                if ($dnmembers) { // for user/group Active Directory
                    if (!is_array($dnmembers)) $dnmembers = array(
                        $dnmembers
                    );
                    
                    foreach ($dnmembers as $gid) {
                        $docu = getDocFromUniqId($gid);
                        if ($docu) {
                            $err = $this->insertDocument($docu->initid);
                            $tnew_docgroupid[] = $dg->initid;
                            if ((!in_array($dg->initid, $t_docgroupid)) && ($err == "")) {
                                $this->addHistoryEntry(sprintf(_("Add to group %s") , $dg->title));
                            }
                        }
                    }
                }
            }
            // suppress for other groups
            $tdiff = array_diff($t_docgroupid, $tnew_docgroupid);
            foreach ($tdiff as $docid) {
                $doc = new_doc($this->dbaccess, $docid);
                $uid = $doc->getRawValue("ldap_uniqid");
                if ($uid) {
                    /**
                     * @var Dir $doc
                     */
                    $err = $doc->removeDocument($this->initid);
                    if ($err == "") {
                        $this->addHistoryEntry(sprintf(_("Delete from group %s") , $doc->title));
                    }
                }
            }
        }
        // if user mail addr has changed, then refresh parent groups
        // to recompute their mail addr
        if ($userMailHasChanged) {
            $coreGroupIdList = array();
            
            $freedomGroupIdList = $this->getMultipleRawValues('us_idgroup');
            foreach ($freedomGroupIdList as $id) {
                $doc = new_Doc($this->dbaccess, $id);
                if (!is_object($doc) || !$doc->isAlive()) {
                    continue;
                }
                array_push($coreGroupIdList, $doc->getRawValue('us_whatid'));
            }
            refreshGroups($coreGroupIdList);
        }
        /*
         * If the user (or group) is not attached to a group, then
         * attach it to the LDAPUSER default US_DEFAULTGROUP group
        */
        $groupList = $user->getGroupsId();
        if (count($groupList) <= 0) {
            $ldapUserFamId = getIdFromName($this->dbaccess, 'LDAPUSER');
            if (is_numeric($ldapUserFamId)) {
                $ldapUserFam = new_Doc($this->dbaccess, $ldapUserFamId, true);
                if (is_object($ldapUserFam)) {
                    $defaultGroupId = $ldapUserFam->getFamilyParameterValue('US_DEFAULTGROUP');
                    $defaultGroup = new_Doc($this->dbaccess, $defaultGroupId, true);
                    if (is_object($defaultGroup) && $defaultGroup->isAlive()) {
                        $err = $defaultGroup->insertDocument($this->initid);
                    }
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
    function getADDN($dn, &$info)
    {
        $err = '';
        include_once "NU/Lib.NU.php";
        $ldaphost = getParam("NU_LDAP_HOST");
        $ldapport = getParam("NU_LDAP_PORT");
        $ldapmode = getParam("NU_LDAP_MODE");
        $ldappw = getParam("NU_LDAP_PASSWORD");
        $ldapbinddn = getParam("NU_LDAP_BINDDN");
        
        $info = array();
        
        $uri = getLDAPUri($ldapmode, $ldaphost, $ldapport);
        $ds = ldap_connect($uri); // must be a valid LDAP server!
        if ($ds) {
            ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
            
            if ($ldapmode == 'tls') {
                $ret = ldap_start_tls($ds);
                if ($ret === false) {
                    $err = sprintf(_("Unable to connect to LDAP server %s") , $uri);
                    @ldap_close($ds);
                    return $err;
                }
            }
            
            $r = ldap_bind($ds, $ldapbinddn, $ldappw);
            if ($r === false) {
                $err = sprintf(_("Unable to bind to LDAP server %s") , $uri);
                @ldap_close($ds);
                return $err;
            }
            // Search login entry
            $filter = "objectclass=*";
            $sr = ldap_read($ds, $dn, $filter);
            $count = ldap_count_entries($ds, $sr);
            if ($count == 1) {
                $info1 = ldap_get_entries($ds, $sr);
                $info0 = $info1[0];
                $entry = ldap_first_entry($ds, $sr);
                
                foreach ($info0 as $k => $v) {
                    if (!is_numeric($k)) {
                        if ($k == "objectsid") {
                            // get binary value from ldap and decode it
                            $values = ldap_get_values_len($ds, $entry, $k);
                            $info[$k] = sid_decode($values[0]);
                        } else {
                            if ($v["count"] == 1) $info[$k] = $v[0];
                            else {
                                if (is_array($v)) unset($v["count"]);
                                $info[$k] = $v;
                            }
                        }
                    }
                }
            } else {
                if ($count == 0) $err = sprintf(_("Cannot find group [%s]") , $dn);
                else $err = sprintf(_("Find mutiple grp with same login  [%s]") , $dn);
            }
            
            ldap_close($ds);
        } else {
            $err = sprintf(_("Unable to connect to LDAP server %s") , $uri);
        }
        
        return $err;
    }
    /**
     * return Active Directory identificator from SID
     * @param string $sid ascii sid
     * @return string the identificator (last number of sid)
     */
    function getADId($sid)
    {
        return substr(strrchr($sid, "-") , 1);
    }
    /**
     * verify if the login syntax is correct and if the login not already exist
     * @param string $login login to test
     * @param $iddomain
     * @return array 2 items $err & $sug for view result of the constraint
     */
    function checkLogin($login, $iddomain)
    {
        $sug = array(
            "-"
        );
        $err = '';
        if ($login != "-") {
            if (preg_match('/^\s*$/', $login)) {
                $err = _("the login must not be empty");
            }
            if ($err == "") {
                return $this->ExistsLogin($login, $iddomain);
            }
        }
        
        return array(
            "err" => $err,
            "sug" => $sug
        );
    }
    /* @begin-method-ignore */
}
/* @end-method-ignore */
?>
