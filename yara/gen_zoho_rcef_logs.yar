
rule EXPL_Zoho_RCE_Fix_Lines_Dec21_1 {
   meta:
      description = "Detects lines in log lines of Zoho products that indicate RCE fixes (silent removal of evidence)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1467784104930385923"
      date = "2021-12-06"
      score = 65
      id = "633287e3-a377-5b3c-8520-a7790168eff5"
   strings:
      // we look for the RCE Fixes
      $s1 = "RCEF="

      // we try to find a line which states that the attack is active (compromised host)
      $sa1 = "\"attackStatus\"\\:\"active\""
      $sa2 = "\"attackStatus\":\"active\""

      // we try to find a line in which the RCE fix deleted a file (compromised host)
      $sd1 = "deletedCount"
      $sd_fp1 = "\"deletedCount\"\\:0"
      $sd_fp2 = "\"deletedCount\":0"
   condition:
      filesize < 6MB and $s1 and (
         1 of ($sa*) or 
         ( $sd1 and not 1 of ($sd_fp*) )
      )
}
