<?php
namespace Dcp\Family {
	/** utilisateur réseau  */
	class Ldapuser extends \\Dcp\Networkuser\LDAPUser { const familyName="LDAPUSER";}
	/** groupe réseau  */
	class Ldapgroup extends \\Dcp\Networkuser\LDAPGroup { const familyName="LDAPGROUP";}
}
namespace Dcp\AttributeIdentifiers {
	/** utilisateur réseau  */
	class Ldapuser extends Iuser {
		/** [frame] LDAP Recherche */
		const us_fr_searchldap='us_fr_searchldap';
		/** [text] login LDAP */
		const ldap_getinfo='ldap_getinfo';
		/** [frame] LDAP Identification */
		const us_fr_ldap='us_fr_ldap';
		/** [text] nom affiché */
		const ldap_displayname='ldap_displayname';
		/** [text] date de création */
		const ldap_createdate='ldap_createdate';
		/** [text] date de modification */
		const ldap_changedate='ldap_changedate';
		/** [text] identifiant unique */
		const ldap_uniqid='ldap_uniqid';
		/** [text] nom LDAP */
		const ldap_dn='ldap_dn';
		/** [frame] AD Identification */
		const us_fr_ad='us_fr_ad';
		/** [text] identifiant */
		const ad_id='ad_id';
		/** [text] groupe primaire */
		const ad_primarygroup='ad_primarygroup';
		/** [action] Actualiser depuis le LDAP */
		const ad_refresh='ad_refresh';
		/** [menu] Affectation des groupes */
		const ad_changegroup='ad_changegroup';
	}
	/** groupe réseau  */
	class Ldapgroup extends Igroup {
		/** [frame] LDAP Identification */
		const grp_fr_ldap='grp_fr_ldap';
		/** [text] date de création */
		const ldap_createdate='ldap_createdate';
		/** [text] date de modification */
		const ldap_changedate='ldap_changedate';
		/** [text] identifiant unique */
		const ldap_uniqid='ldap_uniqid';
		/** [text] nom LDAP */
		const ldap_dn='ldap_dn';
		/** [frame] AD Identification */
		const grp_fr_ad='grp_fr_ad';
		/** [text] identifiant */
		const ad_id='ad_id';
		/** [text] groupe primaire */
		const ad_primarygroup='ad_primarygroup';
	}
}
