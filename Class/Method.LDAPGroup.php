<?php
/*
 * Active Directory Group manipulation
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/
/* @begin-method-ignore */
class _LDAPGROUP extends _IGROUP
{
    /* @end-method-ignore */
    var $defaultview = "FDL:VIEWBODYCARD"; // use default view
    function postModify()
    {
        return parent::postModify();
    }
    /* @begin-method-ignore */
}
/* @end-method-ignore */
?>
