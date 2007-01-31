<?php
// ---------------------------------------------------------------
// $Id: AD_init.php,v 1.1 2007/01/31 17:48:24 eric Exp $
// $Source: /home/cvsroot/anakeen/freedom/networkuser/Attic/AD_init.php,v $
// ---------------------------------------------------------------
//  O   Anakeen - 2001
// O*O  Anakeen development team
//  O   dev@anakeen.com
// ---------------------------------------------------------------
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or (at
//  your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
// ---------------------------------------------------------------

global $app_const;

$app_const= array(
		  "INIT" => "yes",
		  "VERSION" => "0.0.0-0",
		  "AD_HOST"    =>array("val"=>"",
				       "descr"=>N_("host of the LDAP active directory"),
				       "global"=>"Y",
				       "user"=>"N"),
		  "AD_BASE"    =>array("val"=>"",
				       "descr"=>N_("base path of LDAP"),
				       "global"=>"Y",
				       "user"=>"N"),
		  "AD_BINDDN"    =>array("val"=>"",
					 "descr"=>N_("DN of user which can access of all user and group of the LDAP"),
					 "global"=>"Y",
					 "user"=>"N"),
		  "AD_PASSWORD"    =>array("val"=>"",
					   "global"=>"Y",
					   "descr"=>N_("password of the DN"),
					   "user"=>"N"),
		  "LDAP_KIND"    =>array("val"=>"",
					   "global"=>"Y",
					   "descr"=>N_("kind of users LDAP for authentification"),
					   "kind"=>"enum(AD|POSIX)")
		  );

?>
