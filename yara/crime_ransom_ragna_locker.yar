

rule MAL_RANSOM_Ragna_Locker_Apr20_1 {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
   strings:
      $x1 = "---RAGNAR SECRET---" ascii
      $xc1 = { 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 25 73 0D 0A
               25 73 0D 0A 0D 0A 25 73 0D 0A 00 00 2E 00 72 00
               61 00 67 00 6E 00 61 00 72 00 5F }
      $xc2 = { 00 2D 00 66 00 6F 00 72 00 63 00 65 00 00 00 00
               00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C
               00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00
               00 5C 00 6E 00 6F 00 74 00 65 00 70 00 61 00 64
               00 2E 00 65 00 78 00 65 00 }

      $s1 = "bootfont.bin" wide fullword

      $sc2 = { 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00
               00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E
               00 6F 00 6C 00 64 00 00 00 54 00 6F 00 72 00 20
               00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 }

      $op1 = { c7 85 58 ff ff ff 55 00 6b 00 c7 85 5c ff ff ff }
      $op2 = { 50 c7 85 7a ff ff ff 5c }
      $op3 = { 8b 75 08 8a 84 0d 20 ff ff ff ff 45 08 32 06 8b }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 4 of them
}
