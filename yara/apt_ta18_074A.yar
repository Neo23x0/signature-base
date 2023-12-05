/*
   Yara Rule Set
   Author: DHS NCCIC Hunt and Incident Response Team (revised by Florian Roth)
   Date: 2018-03-16
   Identifier: TA18-074A
   Reference: https://www.us-cert.gov/ncas/alerts/TA18-074A
*/

rule WEBSHELL_Z_Webshell_2 {
   meta:
      description = "Detection for the z_webshell"
      author = "DHS NCCIC Hunt and Incident Response Team"
      date = "2018/01/25"
      old_rule_name = "z_webshell"
      md5 =  "2C9095C965A55EFC46E16B86F9B7D6C6"
      id = "9a54925f-de10-567f-a1ea-5e7522b47dfd"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      id = "789ee5e5-83c3-5137-a078-ff230dbf8fcd"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      modified = "2022-08-18"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      id = "4c786098-c5f4-529b-8732-03183dfa94b5"
   strings:
      $s1 = "Running -s cmd /c query user on " ascii
   condition:
      filesize < 600KB and 1 of them
}
