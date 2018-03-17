/*
   Yara Rule Set
   Author: DHS NCCIC Hunt and Incident Response Team (revised by Florian Roth)
   Date: 2018-03-16
   Identifier: TA18-074A
   Reference: https://www.us-cert.gov/ncas/alerts/TA18-074A
*/

rule Query_XML_Code_MAL_DOC_PT_2 {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      name= "Query_XML_Code_MAL_DOC_PT_2"
      author = "other"
   strings:
      $dir1 = "word/_rels/settings.xml.rels"
      $bytes = {8c 90 cd 4e eb 30 10 85 d7}
   condition:
      uint32(0) == 0x04034b50 and $dir1 and $bytes
}

rule Query_Javascript_Decode_Function {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      name= "Query_Javascript_Decode_Function"
      author = "other"
   strings:
      $decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
      $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
      $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
      $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
   condition:
      filesize < 20KB and all of ($decode*)
}

rule z_webshell {
   meta:
      description = "Detection for the z_webshell"
      author = "DHS NCCIC Hunt and Incident Response Team"
      date = "2018/01/25"
      md5 =  "2C9095C965A55EFC46E16B86F9B7D6C6"
   strings:
      $webshell_name = "public string z_progname =" nocase ascii wide
      $webshell_password = "public string Password =" nocase ascii wide
   condition:
      ( uint32(0) == 0x2040253c or uint32(0) == 0x7073613c )
      and filesize < 100KB
      and 2 of ($webshell_*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-16
   Identifier: TA18-074A
   Reference: https://www.us-cert.gov/ncas/alerts/TA18-074A
*/

rule TA18_074A_screen {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
   strings:
      $s1 = "screen.exe" fullword wide
      $s2 = "PlatformInvokeUSER32" fullword ascii
      $s3 = "GetDesktopImageF" fullword ascii
      $s4 = "PlatformInvokeGDI32" fullword ascii
      $s5 = "Too many arguments, going to store in current dir" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and 3 of them
}

rule TA18_074A_scripts {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
   strings:
      $s1 = "Running -s cmd /c query user on " ascii
   condition:
      filesize < 600KB and 2 of them
}
