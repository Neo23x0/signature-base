
rule VUL_Tomcat_Catalina_CVE_2020_1938 {
   meta:
      description = "Detects a possibly active and vulnerable Tomcat configuration that includes an accessible and unprotected AJP connector (you can ignore backup files or files that are not actively used)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.chaitin.cn/en/ghostcat"
      date = "2020-02-28"
      score = 50
      id = "d23af7ce-eb5d-50aa-be02-b4bf858641c2"
   strings:
      $h1 = "<?xml "
      $a1 = "<Service name=\"Catalina\">" ascii

      $v1 = "<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"/>" ascii

      $fp1 = "<!--<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"" ascii
      $fp2 = " secret=\"" ascii
      $fp3 = " requiredSecret=\"" ascii
   condition:
      $h1 at 0 and filesize <= 300KB and
      $a1 and $v1
      and not 1 of ($fp*)
}
