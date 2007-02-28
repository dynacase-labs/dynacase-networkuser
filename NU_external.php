<?php
include_once("NU/Lib.AD.php");
  //function searchLDAPinfo(LDAP_GETINFO):US_LOGIN,US_FNAME,US,LNAME
function searchLDAPinfo($login) {
  $err=searchLDAPFromLogin($login,false,$tinfo);
  $conf=getLDAPconf(getParam("NU_LDAP_KIND"));

  print_r2($tinfo);
  foreach ($tinfo as $k=>$v) {
    $login=$v[$conf["LDAP_USERLOGIN"]];
    $fn=$v["givenName"];
    $ln=$v["sn"];

    $tout[]=array($login,$login,$fn,$ln);
  }
  return $tout;
}
?>