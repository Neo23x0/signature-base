/*
   Yara Rule Set
   Author: US CERT
   Date: 2017-11-15
   Identifier: Hidden Cobra Fall Chill
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-318B
*/

rule TA17_318B_volgmer {
   meta:
      description = "Malformed User Agent in Volgmer malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
   strings:
      $s = "Mozillar/"
   condition:
      ( uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 ) and $s
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-15
   Identifier:
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-318B
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Volgmer_Malware {
   meta:
      description = "Detects Volgmer malware as reported in US CERT TA17-318B"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
      hash1 = "ff2eb800ff16745fc13c216ff6d5cc2de99466244393f67ab6ea6f8189ae01dd"
      hash2 = "8fcd303e22b84d7d61768d4efa5308577a09cc45697f7f54be4e528bbb39435b"
      hash3 = "eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5"
      hash4 = "e40a46e95ef792cf20d5c14a9ad0b3a95c6252f96654f392b4bc6180565b7b11"
      hash5 = "6dae368eecbcc10266bba32776c40d9ffa5b50d7f6199a9b6c31d40dfe7877d1"
      hash6 = "fee0081df5ca6a21953f3a633f2f64b7c0701977623d3a4ec36fff282ffe73b9"
      hash7 = "53e9bca505652ef23477e105e6985102a45d9a14e5316d140752df6f3ef43d2d"
      hash8 = "1d0999ba3217cbdb0cc85403ef75587f747556a97dee7c2616e28866db932a0d"
   strings:
      $x1 = "User-Agent: Mozillar/5.0" fullword ascii
      $x2 = "[Cmd] - CMD_BOTCMD_CONNLOG_GET" fullword wide
      $x3 = "[TestConnect To Bot] - Port = %d" fullword ascii
      $x4 = "b50a338264226b6d57c1936d9db140ba74a28930270a083353645a9b518661f4fcea160d7" ascii

      $s1 = "%sigfx%c%c%c.exe" fullword wide
      $s2 = "H_%s_%016I64X_%04d%02d%02d%02d%02d%02d.TXT" fullword ascii
      $s3 = "cmd.exe /c %s > %s 2>&1" fullword wide
      $s4 = "%s\\dllcache\\%s.dll" fullword ascii
      $s5 = "Cond Fail." fullword ascii
      $s6 = "The %s %s%s" fullword ascii
      $s7 = "%s \"%s\"%s \"%s\" %s \"%s\"" fullword ascii
      $s8 = "DLL_Spider.dll" fullword ascii
   condition:
      filesize < 400KB and (
         1 of ($x*) or /* Very specific strings */
         ( uint16(0) == 0x5a4d and 2 of them ) /* Others combined with the MZ header */
      ) or
      /* Imphash */
      ( uint16(0) == 0x5a4d and pe.imphash() == "ea42395e901b33bad504798e0f0fd74b" )
}