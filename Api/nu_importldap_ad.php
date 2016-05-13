<?php
/*
 * Import Users and groups from a Active Directory server
 *
 * @author Anakeen
 * @package NU
*/

include_once ("FDL/Lib.Attr.php");
include_once ("FDL/Class.DocFam.php");
include_once ("NU/Lib.DocNU.php");

define("SKIPCOLOR", '[1;31;40m');
define("UPDTCOLOR", '[1;32;40m');
define("STOPCOLOR", '[0m');

$conf = getLDAPconf(getParam("NU_LDAP_KIND"));
if (!$conf) {
    print "Kind of LDAP database must be defined: parameter NU_LDAP_KIND.\n";
    exit(1);
}

$dryrun = getHttpVars('dryrun', 'N');
$verbose = getHttpVars('verbose', 'N');
$verbose = ($verbose == 'Y') ? true : false;

$onlygroups = getHttpVars('onlygroups', 'N');
$onlygroups = ($onlygroups == 'Y') ? true : false;

$groups = array();
$err = searchinLDAPGroup($conf, $groups);
if ($err) print "ERROR:$err\n";

$groupdn = array();
$groupdn['*']++;

foreach ($groups as $sid => $group) {
    // print "Search group $sid...\n";
    $doc = getDocFromUniqId($sid);
    
    if (!$doc) {
        
        $groupdn[$group['dn']]++;
        
        if ($dryrun == 'Y') {
            if ($verbose) {
                print "Will create group " . $group['dn'] . "\n";
            }
            continue;
        }
        
        $err = createLDAPGroup($sid, $doc);
        if ($err != "") print SKIPCOLOR;
        if ($verbose) {
            print "Create Group " . $doc->title;
        }
        if ($err != "") print "[$err]\n" . STOPCOLOR;
        if ($verbose) {
            print "\n";
        }
    } else {
        
        $groupdn[$group['dn']]++;
        
        if ($dryrun == 'Y') {
            if ($verbose) {
                print "Will refresh group " . $group['dn'] . "\n";
            }
            continue;
        }
        /* @var \Dcp\Networkuser\NUCommon $doc */
        $err = $doc->refreshFromLDAP();
        if ($err == "") $doc->postStore();
        if ($err != "") print SKIPCOLOR;
        if ($verbose) {
            print "Refresh Group " . $doc->id . $doc->title;
        }
        if ($err != "") print "[$err]\n" . STOPCOLOR;
        if ($verbose) {
            print "\n";
        }
    }
}

if ($onlygroups) {
    exit(0);
}

$userdn = array();

foreach ($groupdn as $group => $v) {
    //$err=searchinLDAP("objectclass=user",$users);
    $memberOf = "(memberOf=" . $group . ")";
    if ($group == '*') {
        $memberOf = "(!(memberOf=*))";
    }
    
    if ($verbose) {
        print "Searching users " . $memberOf . "\n";
    }
    
    $users = array();
    $err = searchinLDAPUser($conf, $users);
    if ($err != '') print "ERROR:$err\n";
    
    foreach ($users as $sid => $user) {
        
        if (array_key_exists($user['dn'], $userdn)) {
            if ($verbose) {
                print "Skipping already processed user " . $user['dn'] . "\n";
            }
            continue;
        }
        $userdn[$user['dn']]++;
        // print "Search user $sid...\n";
        $doc = getDocFromUniqId($sid);
        if (!$doc) {
            
            if ($dryrun == 'Y') {
                if ($verbose) {
                    print "Will create user " . $user['dn'] . "\n";
                }
                continue;
            }
            
            $err = createLDAPUser($sid, $doc);
            if ($err != "") print SKIPCOLOR;
            if ($verbose) {
                print "Create User " . $doc->title;
            }
            if ($err != "") print "[$err]\n" . STOPCOLOR;
            if ($verbose) {
                print "\n";
            }
        } else {
            
            if ($dryrun == 'Y') {
                if ($verbose) {
                    print "Will refresh user " . $user['dn'] . "\n";
                }
                continue;
            }
            
            $err = $doc->refreshFromLDAP();
            if ($err == "") $doc->postStore();
            if ($err != "") print SKIPCOLOR;
            if ($verbose) {
                print "Refresh " . $doc->title;
            }
            if ($err != "") print "[$err]\n" . STOPCOLOR;
            if ($verbose) {
                print "\n";
            }
        }
    }
}

exit(0);
/**
 * return LDAP AD information from the $login
 * @param $conf
 * @param array &$info ldap information
 * @internal param string $login connection identificator
 * @return string error message - empty means no error
 */
function searchinLDAPUser(&$conf, &$info)
{
    $ldapbase = getParam("NU_LDAP_USER_BASE_DN");
    $addfilter = getParam("NU_LDAP_USER_FILTER");
    $filter = sprintf("(&(objectclass=%s)(!(objectclass=computer))%s)", $conf['LDAP_USERCLASS'], $addfilter);
    $ldapuniqid = $conf['LDAP_USERUID'];
    
    return searchinLDAP($ldapbase, $filter, $ldapuniqid, $info);
}

function searchinLDAPGroup(&$conf, &$info)
{
    $ldapbase = getParam("NU_LDAP_GROUP_BASE_DN");
    $addfilter = getParam("NU_LDAP_GROUP_FILTER");
    $filter = sprintf("(&(objectclass=%s)(!(objectclass=computer))%s)", $conf['LDAP_GROUPCLASS'], $addfilter);
    $ldapuniqid = $conf['LDAP_GROUPUID'];
    // Skip creation of groups if the group base dn is empty
    if ($ldapbase == '') {
        return '';
    }
    
    return searchinLDAP($ldapbase, $filter, $ldapuniqid, $info);
}

function searchinLDAP($ldapbase, $filter, $ldapuniqid, &$info)
{
    $err = "";
    $ldaphost = getParam("NU_LDAP_HOST");
    $ldapport = getParam("NU_LDAP_PORT");
    $ldapmode = getParam("NU_LDAP_MODE");
    $ldappw = getParam("NU_LDAP_PASSWORD");
    $ldapbinddn = getParam("NU_LDAP_BINDDN");
    $ldapuniqid = strtolower($ldapuniqid);
    
    if ($ldapbase == '') {
        $err = sprintf("Empty base DN");
        return $err;
    }
    
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
        if ($r) {
            // Search login entry
            $sr = ldap_search($ds, "$ldapbase", $filter);
            if ($sr === false) {
                $err = sprintf(_("Search in base DN '%s' returned with error: %s") , $ldapbase, ldap_error($ds));
                @ldap_close($ds);
                return $err;
            }
            
            $infos = ldap_get_entries($ds, $sr);
            $entry = ldap_first_entry($ds, $sr);
            
            foreach ($infos as $info0) {
                $sid = false;
                if (!is_array($info0)) {
                    continue;
                }
                $info1 = array();
                foreach ($info0 as $k => $v) {
                    if (!is_numeric($k)) {
                        if ($k == "objectsid") {
                            // get binary value from ldap and decode it
                            $values = ldap_get_values_len($ds, $entry, $k);
                            $info1[$k] = sid_decode($values[0]);
                        } else {
                            if (isset($v["count"]) && $v["count"] == 1) {
                                $info1[$k] = $v[0];
                            } else {
                                if (is_array($v)) {
                                    unset($v["count"]);
                                }
                                $info1[$k] = $v;
                            }
                        }
                        if ($k == $ldapuniqid) {
                            $sid = $info1[$k];
                        }
                    }
                }
                if ($sid) {
                    $info[$sid] = $info1;
                } else {
                    $info[] = $info1;
                }
                
                $entry = ldap_next_entry($ds, $entry);
            }
        } else {
            $err = sprintf(_("Unable to bind to LDAP server %s") , $uri);
        }
        ldap_close($ds);
    } else {
        $err = sprintf(_("Unable to connect to LDAP server %s") , $uri);
    }
    
    return $err;
}
