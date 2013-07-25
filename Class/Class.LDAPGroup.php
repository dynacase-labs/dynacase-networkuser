<?php
/*
 * Active Directory Group manipulation
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
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
