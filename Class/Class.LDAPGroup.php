<?php
/*
 * Active Directory Group manipulation
 *
 * @author Anakeen
 * @package NU
*/

namespace Dcp\Networkuser;

use \Dcp\AttributeIdentifiers\Ldapgroup as myAttribute;
use \Dcp\AttributeIdentifiers as Attribute;
use \Dcp\Family\Igroup;

class LDAPGroup extends Igroup
{
    var $defaultview = "FDL:VIEWBODYCARD"; // use default view
    function postStore()
    {
        return parent::postStore();
    }
}
