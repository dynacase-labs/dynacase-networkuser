<?php
/**
 * Active Directory User manipulation
 *
 * @author Anakeen 2007
 * @version $Id: Method.LDAPUser.php,v 1.5 2007/02/28 14:59:33 eric Exp $
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package FREEDOM-AD
 */
 /**
 */


var $defaultview="FDL:VIEWBODYCARD"; // use default view
var $defaultedit="NU:NU_EDIT"; // use default view



function postModify() {
  // nothing
}


function SpecRefresh() {
  // nothing
}

function postCreated() {
  // ldapsearch -x -w anakeen -D "cn=administrateur,cn=users,dc=ad,dc=tlse,dc=i-cesam,dc=com" -b "dc=ad,dc=tlse,dc=i-cesam,dc=com" -h ad.tlse.i-cesam.com 

  $user=$this->getWUser();
  
    if (!$user) {
      $user=new User(""); // create new user
      $this->wuser=&$user;
      
      $login=$this->getValue("us_login");
	$this->wuser->firstname='Unknown';
	$this->wuser->lastname='To Define';
	$this->wuser->login=$login;
	$this->wuser->password_new=uniqid("ad");
	$this->wuser->iddomain="0";
	$this->wuser->famid="LDAPUSER";
	$this->wuser->fid=$this->id;
	$err=$this->wuser->Add(true);

	$this->setValue("US_WHATID",$this->wuser->id);
	$this->modify(false,array("us_whatid"));
	$this->refreshFromAD();
	
	$err=parent::RefreshDocUser();// refresh from core database 
    }
  
  
}
function nu_edit() {
  $this->editattr();
}
?>