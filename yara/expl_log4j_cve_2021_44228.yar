
rule EXPL_Log4j_CVE_2021_44228_Dec21_Soft {
   meta:
      description = "Detects indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      score = 60
   strings:
      $x1 = "${jndi:ldap://"
      $x2 = "${jndi:rmi://"
      $x3 = "${jndi:ldaps://"
   condition:
      1 of them
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard {
   meta:
      description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      score = 80
   strings:
      $x1 = /\$\{jndi:(ldap|ldaps|rmi):\/\/[a-z-\.0-9]{3,42}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
      $fp1r = /(ldap|rmi|ldaps):\/\/(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
   condition:
      $x1 and not 1 of ($fp*)
}
