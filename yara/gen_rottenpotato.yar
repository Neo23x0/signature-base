/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-07
   Identifier: Rotten Potato
*/

/* Rule Set ----------------------------------------------------------------- */

rule RottenPotato_SharpCifs {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file SharpCifs.dll"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07"
      score =65
      hash1 = "7dffb557fc04ceeaf51ab0410d0666a080f32dfedb5ee7620b040a47b776b2f5"
   strings:
      $x1 = "The SAM database on the Windows NT Server does not have a computer account for this workstation trust relationship." fullword wide
      $x2 = "unexpected EOF reading netbios retarget session response" fullword wide
      $x3 = "\\SharpCifs\\obj\\Release\\SharpCifs.pdb"  ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and 1 of them )
}

rule RottenPotato_vshost {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.vshost.exe"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07"
      score = 65
      hash1 = "11a94154c968a033b51b3f04ba39cf7bdc17250ee46da84d418f967b77d1cd5f"
   strings:
      $x1 = "f:\\binaries\\Intermediate\\vsproject" fullword ascii
      $s6 = "vshost-clr2.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule RottenPotato_Potato {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.exe"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07"
      score = 90
      hash1 = "59cdbb21d9e487ca82748168682f1f7af3c5f2b8daee3a09544dd58cbf51b0d5"
   strings:
      $x1 = "Potato.exe -ip <ip>" fullword wide
      $x2 = "-enable_httpserver true -enable_spoof true" fullword wide
      $x3 = "/C schtasks.exe /Create /TN omg /TR" fullword wide
      $x4 = "-enable_token true -enable_dce true" fullword wide
      $x5 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
      $x6 = "DNS lookup fails - UDP Exhaustion worked!" fullword wide
      $x7 = "\\obj\\Release\\Potato.pdb" fullword ascii
      $x8 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide

      $s1 = "\"C:\\Windows\\System32\\cmd.exe\" /K start" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 2 of them )
}

rule RottenPotato_NHttp {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file NHttp.dll"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07"
      score = 65
      hash1 = "4c654b9cdac23e7a3897bcd5cdb2ae19c34aeff70e195e090610112ba3841e78"
   strings:
      $x1 = "\\NHttp\\obj\\Release\\NHttp.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and $x1 )
}
