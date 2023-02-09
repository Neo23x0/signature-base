rule EXT_HKTL_MAL_TinyShell_Backdoor {
   meta:
      author = "Mandiant"
      description = "Detects Tiny Shell - an open-source UNIX backdoor"
      date = "2022-03-17"
      reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
      score = 80
      hash1 = "1f889871263bd6cdad8f3d4d5fc58b4a32669b944d3ed0860730374bb87d730a"
   strings:
      $sb1 = { C6 00 48 C6 4? ?? 49 C6 4? ?? 49 C6 4? ?? 4C C6 4? ?? 53 C6 4? ?? 45 C6 4? ?? 54 C6 4? ?? 3D C6 4? ?? 46 C6 4? ?? 00 }
      $sb2 = { C6 00 54 C6 4? ?? 4D C6 4? ?? 45 C6 4? ?? 3D C6 4? ?? 52 }
      $ss1 = "fork" ascii fullword wide
      $ss2 = "socket" ascii fullword wide
      $ss3 = "bind" ascii fullword wide
      $ss4 = "listen" ascii fullword wide
      $ss5 = "accept" ascii fullword wide
      $ss6 = "alarm" ascii fullword wide
      $ss7 = "shutdown" ascii fullword wide
      $ss8 = "creat" ascii fullword wide
      $ss9 = "write" ascii fullword wide
      $ss10 = "open" ascii fullword wide
      $ss11 = "read" ascii fullword wide
      $ss12 = "execl" ascii fullword wide
      $ss13 = "gethostbyname" ascii fullword wide
      $ss14 = "connect" ascii fullword wide
   condition:
      uint32(0) == 0x464c457f and 1 of ($sb*) and 10 of ($ss*)
}

rule EXT_HKTL_MAL_TinyShell_Backdoor_SPARC {
   meta:
      author = "Mandiant"
      description = "Detects Tiny Shell variant for SPARC - an open-source UNIX backdoor"
      date = "2022-03-17"
      reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
      score = 80
   strings:
      $sb_xor_1 = { DA 0A 80 0C 82 18 40 0D C2 2A 00 0B 96 02 E0 01 98 03 20 01 82 1B 20 04 80 A0 00 01 82 60 20 00 98 0B 00 01 C2 4A 00 0B 80 A0 60 00 32 BF FF F5 C2 0A 00 0B 81 C3 E0 08 }
      $sb_xor_2 = { C6 4A 00 00 80 A0 E0 00 02 40 00 0B C8 0A 00 00 85 38 60 00 C4 09 40 02 84 18 80 04 C4 2A 00 00 82 00 60 01 80 A0 60 04 83 64 60 00 10 6F FF F5 90 02 20 01 81 C3 E0 08 }
   condition:
      uint32(0) == 0x464C457F and (uint16(0x10) & 0x0200 == 0x0200) and (uint16(0x12) & 0x0200 == 0x0200) and 1 of them
}

rule EXT_APT_UNC2891_SLAPSTICK {
   meta:
      author = "Mandiant"
      description = "Detects SLAPSTICK malware used by UNC2891"
      date = "2022-03-17"
      reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
      score = 80
   strings:
      $ss1 = { 25 59 20 25 62 20 25 64 20 25 48 3a 25 4d 3a 25 53 20 20 20 20 00 }
      $ss2 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 00 }
      $ss3 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 73 0a 00 }
   condition:
      (uint32(0) == 0x464c457f) and all of them
}

