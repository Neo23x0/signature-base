
rule APT_MAL_DTRACK_Oct19_1 {
   meta:
      description = "Detects DTRACK malware"
      author = "Florian Roth (Nextron Systems)"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      reference = "https://twitter.com/a_tweeter_user/status/1188811977851887616?s=21"
      date = "2019-10-28"
      hash1 = "c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c"
      hash2 = "a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68"
      hash3 = "93a01fbbdd63943c151679d037d32b1d82a55d66c6cb93c40ff63f2b770e5ca9"
      hash4 = "3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682"
      hash5 = "bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364"
      hash6 = "58fef66f346fe3ed320e22640ab997055e54c8704fc272392d71e367e2d1c2bb"
      hash7 = "9d9571b93218f9a635cfeb67b3b31e211be062fd0593c0756eb06a1f58e187fd"
      id = "802135bd-234d-574d-b111-fcc9eaa000f8"
   strings:
      $xc1 = { 25 73 2A 2E 2A 00 00 00 5C 00 00 00 25 73 7E 00
               5C 00 00 00 77 62 00 00 64 61 74 00 64 6B 77 65
               72 6F 33 38 6F 65 72 41 5E 74 40 23 00 00 00 00
               63 3A 5C 00 25 73 5C 25 63 2E 74 6D 70 }

      $sx1 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d : " fullword ascii
      $sx2 = "%s\\%c.tmp" fullword ascii
      $sx3 = "dkwero38oerA" fullword ascii
      $sx4 = "awz2qr21yfbj" fullword ascii

      $s1 = "Execute_%s.log" ascii
      $s2 = "%s\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" fullword ascii
      $s3 = "CCS_Mozilla/5.0" fullword ascii
      $s4 = "\\C$\\Windows\\Temp\\MpLogs\\" ascii
      $s5 = "127.0.0.1 >NUL & echo EEEE > \"%s\"" fullword ascii
      $s6 = "[+] DownloadCommand" fullword ascii
      $s7 = "DC-Error: Too long cmd length" fullword ascii
      $s8 = "%s\\~%d.tmp" fullword ascii
      $s9 = "%02X:%02X:%02X:%02X:%02X:%02X" ascii fullword

      $op1 = { 0f b6 8d a3 fc ff ff 85 c9 74 09 8b 55 f4 83 c2 }
      $op2 = { 6a 00 8d 85 28 fc ff ff 50 6a 04 8d 4d f8 51 8b }
      $op3 = { 8b 85 c8 fd ff ff 03 85 a4 fc ff ff 89 85 b4 fc }
   condition:
      $xc1 or 2 of ($sx*) or 4 of them or
      ( uint16(0) == 0x5a4d and filesize <= 3000KB and 2 of them )
}
