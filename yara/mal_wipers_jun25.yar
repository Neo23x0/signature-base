
rule MAL_WIPER_Unknown_Jun25 {
   meta:
      description = "Detects unknown disk wiper first spotted in June 2025 and uploaded from Israel"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 75
      hash1 = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
   strings:
      $x1 = "\\CWipeNew\\Release\\" ascii fullword

      $s1 = "Failed to get disk geometry: " wide fullword
      $s2 = "--- Working on " wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}
