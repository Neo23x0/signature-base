
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
rule SUSP_LNX_SH_Disk_Wiper_Script_Jun25 {
   meta:
      description = "Detects unknown disk wiper script for Linux systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-06-19"
      score = 65
      hash1 = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
   strings:
      $s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
      $s2 = "FAIR WARNING!" ascii fullword
      $s3 = "lists devices" ascii fullword
   condition:
      uint16(0) == 0x2123
      and filesize < 2KB
      and all of them
}

rule SUSP_PY_PYInstaller_Swiper_Jun25 {
   meta:
      description = "Detects suspicious Python based executable with similarities to a known disk wiper"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 65
      hash1 = "4f669ecbe12e95d51f37be76933de4c2626d20bb01729086ce2efc603c4ffdf3"
   strings:
      $a1 = "bzlib1.dll" ascii fullword
      $a2 = "VCRUNTIME140_1.dll" wide fullword
      $a3 = "%s%c%s.exe" ascii fullword

      $sc1 = { 73 77 69 70 65 72 00 00 00 } // "swiper\0\0\0"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 40000KB
      and all of them
}