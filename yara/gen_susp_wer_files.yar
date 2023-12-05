
rule SUSP_WER_Critical_HeapCorruption {
   meta:
      description = "Detects a crashed application that crashed due to a heap corruption error (could be a sign of exploitation)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1185459425710092288"
      date = "2019-10-18"
      score = 45
      id = "2b1dad5f-cc2c-5d8c-8275-ebb56d079895"
   strings:
      $a1 = "ReportIdentifier=" wide
      $a2 = ".Name=Fault Module Name" wide

      $s1 = "c0000374" wide /* Heap Corruption */
   condition:
      ( uint32be(0) == 0x56006500 or uint32be(0) == 0xfffe5600 )
      and all of them
}

rule SUSP_WER_Suspicious_Crash_Directory {
   meta:
      description = "Detects a crashed application executed in a suspicious directory"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1185585050059976705"
      date = "2019-10-18"
      score = 45
      id = "bf91e20c-aa35-5b13-86ed-a63e6fb4d1a2"
   strings:
      $a1 = "ReportIdentifier=" wide
      $a2 = ".Name=Fault Module Name" wide
      $a3 = "AppPath=" wide nocase

      /* Whitelist */
      $l1 = "AppPath=C:\\Windows\\" wide nocase
      $l2 = "AppPath=C:\\Program" wide nocase
      $l3 = "AppPath=C:\\Python" wide nocase
      $l4 = "AppPath=C:\\Users\\" wide nocase

      /* Blacklist */
      /* covered via Whitelist
      $s1 = "AppPath=C:\\$Recycle.Bin\\" wide
      $s2 = "AppPath=C:\\Perflogs\\" wide
      $s3 = "AppPath=C:\\Temp\\" wide
      $s4 = "AppPath=\\\\" wide // network share, or \\tsclient\c etc.
      $s5 = /AppPath=[C-Z]:\\\\[^\\]{1,64}\.exe/ wide nocase // in the root of a partition - no sub folder
      */
      $s6 = "AppPath=C:\\Users\\Public\\" nocase wide
      $s7 = "AppPath=C:\\Users\\Default\\" nocase wide
      /* Root of AppData */
      $s8 = /AppPath=C:\\Users\\[^\\]{1,64}\\AppData\\(Local|Roaming)\\[^\\]{1,64}\.exe/ wide nocase
   condition:
      ( uint32be(0) == 0x56006500 or uint32be(0) == 0xfffe5600 )
      and all of ($a*) and ( not 1 of ($l*) or 1 of ($s*) )
}
