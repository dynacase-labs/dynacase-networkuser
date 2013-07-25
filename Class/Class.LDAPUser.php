<?php
/*
 * Active Directory User manipulation
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/

namespace Dcp\Networkuser;

use \Dcp\AttributeIdentifiers\Ldapuser as myAttribute;
use \Dcp\AttributeIdentifiers as Attribute;
use \Dcp\Family\Iuser;

class LDAPUser extends Iuser
{
    var $defaultview = "FDL:VIEWBODYCARD"; // use default view
    var $defaultedit = "FDL:EDITBODYCARD"; // use default view
    var $defaultcreate = "NU:NU_EDIT"; // use default view
    function postCreated()
    {
        $user = $this->getAccount();
        
        if (!$user) {
            $user = new \Account(""); // create new user
            $this->wuser = & $user;
            
            $login = $this->getRawValue(myAttribute::us_login);
            $this->wuser->firstname = 'Unknown';
            $this->wuser->lastname = 'To Define';
            $this->wuser->login = $login;
            $this->wuser->password_new = uniqid("ad");
            $this->wuser->famid = "LDAPUSER";
            $this->wuser->fid = $this->id;
            $err = $this->wuser->Add(true);
            
            $this->setValue(myAttribute::us_whatid, $this->wuser->id);
            $this->modify(false, array(
                myAttribute::us_whatid
            ));
            $this->refreshFromLDAP();
            
            $err.= parent::RefreshDocUser(); // refresh from core database
            if ($err) {
                error_log(__METHOD__ . $err);
            }
        }
    }
    /**
     * @templateController
     */
    function nu_edit()
    {
        $this->editattr(true);
    }
}
