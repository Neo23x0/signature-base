
rule LOG_EXPL_SUSP_TeamCity_CVE_2023_42793_Oct23_1 {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of CVE-2023-42793 on TeamCity servers"
      author = "Florian Roth"
      reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
      date = "2023-10-02"
      score = 70
      id = "81c04863-72aa-5515-889e-3ef718360cac"
   strings:
      $sa1 = "File edited: "
      $sa2 = "\\TeamCity\\config\\internal.properties by user with id="
      
      $sb1 = "s.buildServer.ACTIVITIES.AUDIT - server_file_change: File "
      $sb2 = "\\TeamCity\\config\\internal.properties was modified by \"user with id"
   condition:
      all of ($sa*) or all of ($sb*)
}

rule LOG_EXPL_SUSP_TeamCity_Oct23_1 {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of TeamCity servers"
      author = "Florian Roth"
      reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
      date = "2023-10-02"
      score = 70
      id = "4845b40a-cf77-53ae-b2fa-d1ed861153f2"
   strings:
      $a1 = "tbrains.buildServer.ACTIVITIES"
      $s1 = "External process is launched by user user with id"
      $s2 = ". Command line: cmd.exe \"/c whoami"
   condition:
      all of them
}
