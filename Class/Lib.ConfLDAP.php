<?php
/*
 * LDAP configuration
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/

function getLDAPconf($type, $attr = false)
{
    $conf = false;
    switch ($type) {
        case 'AD':
            $conf = array(
                "LDAP_USERCLASS" => "user",
                "LDAP_USERLOGIN" => "sAMAccountName",
                "LDAP_USERUID" => "objectSid",
                "LDAP_GROUPCLASS" => "group",
                "LDAP_GROUPLOGIN" => "sAMAccountName",
                "LDAP_GROUPUID" => "objectSid"
            );
            break;

        case 'POSIX':
            $conf = array(
                "LDAP_USERCLASS" => "posixAccount",
                "LDAP_USERLOGIN" => "uid",
                "LDAP_USERUID" => "uidNumber",
                "LDAP_GROUPCLASS" => "posixGroup",
                "LDAP_GROUPLOGIN" => "cn",
                "LDAP_GROUPUID" => "gidNumber"
            );
            break;

        case 'INET':
            $conf = array(
                "LDAP_USERCLASS" => "inetOrgPerson",
                "LDAP_USERLOGIN" => "uid",
                "LDAP_USERUID" => "uid",
                "LDAP_GROUPCLASS" => "posixGroup",
                "LDAP_GROUPLOGIN" => "cn",
                "LDAP_GROUPUID" => "gidNumber"
            );
            break;
    }
    
    if ($conf && $attr) return $conf[$attr];
    return $conf;
}
?>