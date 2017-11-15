
/*
   Yara Rule Set
   Author: US CERT
   Date: 2017-11-15
   Identifier: Hidden Cobra Fall Chill
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-318A
*/

rule TA17_318A_rc4_stack_key_fallchill {
   meta:
      description = "HiddenCobra FallChill - rc4_stack_key"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
   strings:
      $stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $stack_key
}

rule TA17_318A_success_fail_codes_fallchill {
   meta:
      description = "HiddenCobra FallChill - success_fail_codes"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
   strings:
      $s0 = { 68 7a 34 12 00 }
      $s1 = { ba 7a 34 12 00 }
      $f0 = { 68 5c 34 12 00 }
      $f1 = { ba 5c 34 12 00 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and (($s0 and $f0) or ($s1 and $f1))
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-15
   Identifier: Hidden Cobra Fall Chill
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-318A
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule HiddenCobra_FallChill_1 {
   meta:
      description = "Auto-generated rule - file a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
      date = "2017-11-15"
      hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
   strings:
      $s1 = "REGSVR32.EXE.MUI" fullword wide
      $s2 = "Microsoft Corporation. All rights reserved." fullword wide
      $s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
      $s4 = "\" goto Loop" fullword ascii

      $e1 = "xolhvhlxpvg" fullword ascii
      $e2 = "tvgslhgybmanv" fullword ascii
      $e3 = "CivagvTllosvok32Smakhslg" fullword ascii
      $e4 = "GvgCfiivmgDrivxglibW" fullword ascii
      $e5 = "OkvmPilxvhhTlpvm" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
        pe.imphash() == "6135d9bc3591ae7bc72d070eadd31755" or
        3 of ($s*) or
        4 of them
      )
}

rule HiddenCobra_FallChill_2 {
   meta:
      description = "Auto-generated rule - file 0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
      date = "2017-11-15"
      hash1 = "0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"
   strings:
      $s1 = "%s\\%s.dll" fullword wide
      $s2 = "yurdkr.dll" fullword ascii
      $s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "cb36dcb9909e29a38c387b8a87e7e4ed" or
         ( 2 of them )
      )
}