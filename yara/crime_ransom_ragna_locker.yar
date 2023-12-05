import "pe"

rule MAL_RANSOM_Ragna_Locker_Apr20_1 {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      id = "67164cb4-73b7-5c4e-88f9-42379b88c641"
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

rule MAL_Ransom_Ragnarlocker_July_2020_1 {
   meta:
      description = "Detects Ragnarlocker by strings (July 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1288797666688851969"
      date = "2020-07-30"
      hash1 = "04c9cc0d1577d5ee54a4e2d4dd12f17011d13703cdd0e6efd46718d14fd9aa87"
      id = "60e09057-d9f8-5e89-8f47-c5dda32806c6"
   strings:
      $f1 = "bootfont.bin" fullword wide
      $f2 = "bootmgr.efi" fullword wide
      $f3 = "bootsect.bak" fullword wide
      $r1 = "$!.txt" fullword wide
      $r2 = "---BEGIN KEY R_R---" fullword ascii
      $r3 = "!$R4GN4R_" wide
      $r4 = "RAGNRPW" fullword ascii /* parser */
      $r5 = "---END KEY R_R---" fullword ascii
      $a1 = "+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0" fullword ascii    
      $a2 = "\\\\.\\PHYSICALDRIVE%d" fullword wide /* parse disks */
      $a3 = "WinSta0\\Default" fullword wide /* Token ref */
      $a4 = "%s-%s-%s-%s-%s" fullword wide /* GUID parser*/
      $a5 = "SOFTWARE\\Microsoft\\Cryptography" fullword wide /* Ref crypto used */
      $c1 = "-backup" fullword wide
      $c2 = "-force" fullword wide
      $c3 = "-vmback" fullword wide
      $c4 = "-list" fullword wide
      $s1 = ".ragn@r_" wide /* ref */
      $s2 = "\\notepad.exe" wide /* Show ransom note to the victim*/
      $s3 = "Opera Software" fullword wide  /* Don't touch browsers for contact him*/
      $s4 = "Tor browser" fullword wide /*Ref ransom note*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( pe.imphash() == "2c2aab89a4cba444cf2729e2ed61ed4f" and ( (2 of ($f*)) and (3 of ($r*)) and (4 of ($a*)) and (2 of ($c*)) and (2 of ($s*)) ) )
}