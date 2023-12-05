
rule EXPL_Exchange_ProxyNotShell_Patterns_CVE_2022_41040_Oct22_1 : SCRIPT {
   meta:
      description = "Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information)"
      author = "Florian Roth (Nextron Systems)"
      score = 75
      old_rule_name = "EXPL_Exchange_ProxyNoShell_Patterns_CVE_2022_41040_Oct22_1"
      reference = "https://github.com/kljunowsky/CVE-2022-41040-POC"
      date = "2022-10-11"
      modified = "2023-03-15"
      id = "d2812fcd-0a20-5bbd-a9e1-9cca1ed58aa3"
   strings:
      $sr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}owershell/ nocase ascii

      $sa1 = " 200 "

      $fp1 = " 444 "
      $fp2 = " 404 "
      $fp2b = " 401 " /* Unauthorized */
      $fp3 = "GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId=" ascii /* Nessus */
      $fp4 = "@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com" ascii /* Nessus */
   condition:
      $sr1
      and 1 of ($sa*)
      and not 1 of ($fp*)
}
