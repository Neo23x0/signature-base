
rule LOG_ProxyNotShell_POC_CVE_2022_41040_Nov22 {
   meta:
      description = "Detects logs generated after a successful exploitation using the PoC code against CVE-2022-41040 and CVE-2022-41082 (aka ProxyNotShell) in Microsoft Exchange servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/testanull/ProxyNotShell-PoC"
      date = "2022-11-17"
      score = 70
      id = "1e47d124-3103-5bf5-946f-b1bb69ff2c8e"
   strings:
      $aa1 = " POST " ascii wide
      $aa2 = " GET " ascii wide

      $ab1 = " 200 " ascii wide

      $s01 = "/autodiscover.json x=a" ascii wide
      $s02 = "/autodiscover/admin@localhost/" ascii wide
   condition:
      1 of ($aa*) and $ab1 and 1 of ($s*)
}
