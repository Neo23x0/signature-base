
rule VULN_Confluence_Questions_Plugin_CVE_2022_26138_Jul22_1 {
   meta:
      description = "Detects properties file of Confluence Questions plugin with static user name and password (backdoor) CVE-2022-26138"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/security/atlassian-fixes-critical-confluence-hardcoded-credentials-flaw/"
      date = "2022-07-21"
      score = 50
      id = "1443c673-2a86-5431-876a-c8fccba52190"
   strings:
      $x_plain_1 = "predefined.user.password=disabled1system1user6708"

      $jar_marker = "/confluence/plugins/questions/"
      /*                 v this is the size of 204 bytes              */
      $jar_size_1 = { 00 CC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
      /*    here starts default.properties v                          */
                      ?? ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70
                      72 6F 70 65 72 74 69 65 73 50 4B }
      $jar_size_2 = { 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74
                      2E 70 72 6F 70 65 72 74 69 65 73 }
   condition:
      1 of ($x*) or ( $jar_marker and 1 of ($jar_size*) )
}

