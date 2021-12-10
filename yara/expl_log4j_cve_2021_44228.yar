
rule EXPL_Log4j_CVE_2021_44228_Dec21_1 {
   meta:
      description = "Detects indicators in server logs that indicate the sucessful exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      score = 80
   strings:
      $xr1 = /Send LDAP reference result for [\w]{1,32} redirecting to http[s]?://[^\n]{10,80}\.class/
      $s1 = "Log a requests to http://"
   condition:
      all of them
}
