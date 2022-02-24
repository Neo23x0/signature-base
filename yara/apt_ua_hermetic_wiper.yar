
rule APT_UA_Hermetic_Wiper_Feb22_1 {
   meta:
      description = "Detects Hermetic Wiper malware"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
      date = "2022-02-24"
      score = 75
      hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
      hash2 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
      hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
      hash4 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
   strings:
      $xc1 = { 00 5C 00 5C 00 2E 00 5C 00 50 00 68 00 79 00 73
               00 69 00 63 00 61 00 6C 00 44 00 72 00 69 00 76
               00 65 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 45 00 50 00 4D 00 4E 00 54 00 44 00 52 00 56
               00 5C 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 00 00 00 00 25 00 73 00 25 00 2E 00 32 00 73
               00 00 00 00 00 24 00 42 00 69 00 74 00 6D 00 61
               00 70 00 00 00 24 00 4C 00 6F 00 67 00 46 00 69
               00 6C 00 65 }
      $sc1 = { 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 00
               00 64 00 72 00 76 00 00 00 53 00 79 00 73 00 74
               00 65 00 6D 00 33 00 32 }

      $s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
      $s2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
      $s3 = "DRV_XP_X64" wide fullword
      $s4 = "%ws%.2ws" wide fullword

      $op1 = { 8b 7e 08 0f 57 c0 8b 46 0c 83 ef 01 66 0f 13 44 24 20 83 d8 00 89 44 24 18 0f 88 3b 01 00 00 }
      $op2 = { 13 fa 8b 55 f4 4e 3b f3 7f e6 8a 45 0f 01 4d f0 0f 57 c0 }
   condition:
      ( uint16(0) == 0x5a53 or uint16(0) == 0x5a4d ) and
      filesize < 400KB and ( 1 of ($x*) or 3 of them )
}
