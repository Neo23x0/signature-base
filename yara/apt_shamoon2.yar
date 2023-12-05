/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-01
   Identifier: Shamoon 2.0
*/

/* Rule Set ----------------------------------------------------------------- */

rule Shamoon2_Wiper {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
      id = "6660a64c-daa4-59e6-aa65-55194cac600c"
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule Shamoon2_ComComp {
   meta:
      description = "Detects Shamoon 2.0 Communication Components"
      author = "Florian Roth (Nextron Systems) (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
      id = "72068264-4f71-59fb-b3d8-938285ec8c7f"
   strings:
      $s1 = "mkdir %s%s > nul 2>&1" fullword ascii
      $s2 = "p[%s%s%d.%s" fullword ascii

      $op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 }
      $op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d }
      $op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and ( all of ($s*) or all of ($op*) )
}

rule EldoS_RawDisk {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth (Nextron Systems) (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      modified = "2023-01-27"
      score = 50
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      id = "8a43f425-86b7-5a05-b7c3-13c78aa905f8"
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them )
}
