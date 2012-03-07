<?php
/*
 * Active Directory User manipulation
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/
/* @begin-method-ignore */
class _LDAPUSER extends _IUSER
{
    /* @end-method-ignore */
    var $defaultview = "FDL:VIEWBODYCARD"; // use default view
    var $defaultedit = "FDL:EDITBODYCARD"; // use default view
    var $defaultcreate = "NU:NU_EDIT"; // use default view
    function postModify()
    {
        // not call parent
        $err = $this->setGroups();
        if ($err == "") {
            $err = $this->RefreshDocUser(); // refresh from core database
            //$errldap=$this->RefreshLdapCard();
            //if ($errldap!="") AddWarningMsg($errldap);
            
        }
    }
    
    function postCreated()
    {
        // ldapsearch -x -w anakeen -D "cn=administrateur,cn=users,dc=ad,dc=tlse,dc=i-cesam,dc=com" -b "dc=ad,dc=tlse,dc=i-cesam,dc=com" -h ad.tlse.i-cesam.com
        $user = $this->getWUser();
        
        if (!$user) {
            $user = new User(""); // create new user
            $this->wuser = & $user;
            
            $login = $this->getValue("us_login");
            $this->wuser->firstname = 'Unknown';
            $this->wuser->lastname = 'To Define';
            $this->wuser->login = $login;
            $this->wuser->password_new = uniqid("ad");
            $this->wuser->iddomain = "0";
            $this->wuser->famid = "LDAPUSER";
            $this->wuser->fid = $this->id;
            $err = $this->wuser->Add(true);
            
            $this->setValue("US_WHATID", $this->wuser->id);
            $this->modify(false, array(
                "us_whatid"
            ));
            $this->refreshFromLDAP();
            
            $err = parent::RefreshDocUser(); // refresh from core database
            
        }
    }
    function nu_edit()
    {
        $this->editattr(true);
    }
    /* @begin-method-ignore */
}
/* @end-method-ignore */
?>
