import "pe"

rule MAL_Trickbot_Oct19_1 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b428cbf9-0796-5a01-9b98-28e1bc6827cc"
   strings:
      $s1 = "Celestor@hotmail.com" fullword ascii
      $s2 = "\\txtPassword" ascii
      $s14 = "Invalid Password, try again!" fullword wide

      $op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
      $op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 3 of them
}

rule MAL_Trickbot_Oct19_2 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      id = "2ff69a51-d089-53e5-ab19-4fbdf20f90f8"
   strings:
      $x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
      $x2 = "AxedWV3OVTFfnGb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Oct19_3 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash3 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      hash4 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash5 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      id = "3428b7e3-def9-5574-bbbb-6ba98c134dec"
   strings:
      $s1 = "Decrypt Shell Fail" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of them or pe.imphash() == "4e3fbfbf1fc23f646cd40a6fe09385a7" )
}

rule MAL_Trickbot_Oct19_4 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      hash3 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash4 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      id = "dcadaa50-52ae-5ded-b40e-149f28092093"
   strings:
      $x1 = "c:\\users\\user\\documents\\visual studio 2005\\projects\\adzxser\\release\\ADZXSER.pdb" fullword ascii
      $x2 = "http://root-hack.org" fullword ascii
      $x3 = "http://hax-studios.net" fullword ascii
      $x4 = "5OCFBBKCAZxWUE#$_SVRR[SQJ" fullword ascii
      $x5 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Oct19_5 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      hash4 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b3034f0c-5fd9-58a2-866f-9100e3a56f39"
   strings:
      $s1 = "LoadShellCode" fullword ascii
      $s2 = "pShellCode" fullword ascii
      $s3 = "InitShellCode" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 2 of them
}

rule MAL_Trickbot_Oct19_6 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      hash2 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      id = "5feb8d34-4974-5315-a5f9-79a3fac83d1d"
   strings:
      $x1 = "D:\\MyProjects\\spreader\\Release\\ssExecutor_x86.pdb" fullword ascii

      $s1 = "%s\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s" fullword ascii
      $s2 = "%s\\appdata\\roaming\\%s" fullword ascii
      $s3 = "WINDOWS\\SYSTEM32\\TASKS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 400KB and ( 1 of ($x*) or 3 of them )
}
