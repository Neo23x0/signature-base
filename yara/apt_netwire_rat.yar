/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-05
   Identifier: NetWire
   Reference: https://pastebin.com/8qaiyPxs
*/

/* Rule Set ----------------------------------------------------------------- */

rule Susp_Indicators_EXE {
   meta:
      description = "Detects packed NullSoft Inst EXE with characteristics of NetWire RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/8qaiyPxs"
      date = "2018-01-05"
      score = 60
      hash1 = "6de7f0276afa633044c375c5c630740af51e29b6a6f17a64fbdd227c641727a4"
      id = "b4015c24-d18e-51eb-9854-8cc0e6dba4d0"
   strings:
      $s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
      $s2 = "Error! Bad token or internal error" fullword ascii
      $s3 = "CRYPTBASE" fullword ascii
      $s4 = "UXTHEME" fullword ascii
      $s5 = "PROPSYS" fullword ascii
      $s6 = "APPHELP" fullword ascii
   condition:
   uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and filesize < 700KB and all of them
}

rule Suspicious_BAT_Strings {
   meta:
      description = "Detects a string also used in Netwire RAT auxilliary"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://pastebin.com/8qaiyPxs"
      date = "2018-01-05"
      id = "5fe28555-96c8-54da-b047-7d0a7532a6d2"
   strings:
      $s1 = "ping 192.0.2.2 -n 1" ascii
   condition:
      filesize < 600KB and 1 of them
}

rule Malicious_BAT_Strings {
   meta:
      description = "Detects a string also used in Netwire RAT auxilliary"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://pastebin.com/8qaiyPxs"
      date = "2018-01-05"
      id = "6e197d05-62eb-535d-8cd6-db8550e51588"
   strings:
      $s1 = "call :deleteSelf&exit /b"
   condition:
      filesize < 600KB and 1 of them
}
