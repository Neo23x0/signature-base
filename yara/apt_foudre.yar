/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-01
   Identifier: Foudre
   Reference: https://goo.gl/Nbqbt6
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Foudre_Backdoor_1 {
   meta:
      description = "Detects Foudre Backdoor"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/Nbqbt6"
      date = "2017-08-01"
      hash1 = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
      hash2 = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"
      id = "ab2d43f4-fc35-5980-9b5d-98c5c4cfd012"
   strings:
      $s1 = "initialization failed: Reinstall the program" fullword wide
      $s2 = "SnailDriver V1" fullword wide
      $s3 = "lp.ini" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 2 of them )
}

rule Foudre_Backdoor_Dropper_1 {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/Nbqbt6"
      date = "2017-08-01"
      modified = "2023-01-07"
      hash1 = "6bc9f6ac2f6688ed63baa29913eaf8c64738cf19933d974d25a0c26b7d01b9ac"
      hash2 = "da228831089c56743d1fbc8ef156c672017cdf46a322d847a270b9907def53a5"
      id = "38c7d05b-d545-53c5-8db7-a7925b5b7838"
   strings:
      $x1 = "536F594A96C5496CB3949A4DA4775B576E049C57696E646F77735C43757272656E7456657273696F6E5C5C52756E" fullword wide
      $x2 = "2220263024C380B3278695851482EC32" fullword wide

      $s1 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\\\Startup\\" wide
      $s2 = "C:\\Documents and Settings\\All Users\\" wide
      $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\\\Shell Folders" wide
      $s4 = "ShellExecuteW" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 4 of them ) )
}

rule Foudre_Backdoor_Component_1 {
   meta:
      description = "Detects Foudre Backdoor"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/Nbqbt6"
      date = "2017-08-01"
      modified = "2023-01-07"
      hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
      hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"
      id = "9070f581-64a7-5620-aff4-7f2cbd73099d"
   strings:
      /* $s1 = "Project1.dll" fullword ascii */
      /* Better: Project1.dll\x00D1 */
      $s1 = { 50 72 6F 6A 65 63 74 31 2E 64 6C 6C 00 44 31 }
      $s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
      $s3 = "C:\\Documents and Settings\\All Users\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and
         ( 3 of them ) or
         ( 2 of them and pe.exports("D1") )
      )
}

rule Foudre_Backdoor_SFX {
   meta:
      description = "Detects Foudre Backdoor SFX"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/Nbqbt6"
      date = "2017-08-01"
      hash1 = "2b37ce9e31625d8b9e51b88418d4bf38ed28c77d98ca59a09daab01be36d405a"
      hash2 = "4d51a0ea4ecc62456295873ff135e4d94d5899c4de749621bafcedbf4417c472"
      id = "b5c7cd6b-48c8-5703-b695-19d226de1810"
   strings:
      $s1 = "main.exe" fullword ascii
      $s2 = "pub.key" fullword ascii
      $s3 = "WinRAR self-extracting archive" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}
