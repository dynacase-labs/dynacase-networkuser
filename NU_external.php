<?php
include_once("NU/Lib.NU.php");
  //function searchLDAPinfo(LDAP_GETINFO):US_LOGIN,US_FNAME,US,LNAME
function searchLDAPinfo($login) {
  $err=searchLDAPFromLogin($login,false,$tinfo);
  $conf=getLDAPconf(getParam("NU_LDAP_KIND"));

  print_r2($tinfo);
  foreach ($tinfo as $k=>$v) {
    $login=utf8_decode($v[$conf["LDAP_USERLOGIN"]]);
    $fn=utf8_decode($v["givenName"]);
    $ln=utf8_decode($v["sn"]);

    $tout[]=array($login,$login,$fn,$ln);
  }
  return $tout;
}
?>