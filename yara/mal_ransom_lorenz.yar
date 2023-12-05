rule MAL_RANSOM_Lorenz_May21_1 {
   meta:
      description = "Detects Lorenz Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - DACH TE"
      date = "2021-05-04"
      hash1 = "4b1170f7774acfdc5517fbe1c911f2bd9f1af498f3c3d25078f05c95701cc999"
      hash2 = "8258c53a44012f6911281a6331c3ecbd834b6698b7d2dbf4b1828540793340d1"
      hash3 = "c0c99b141b014c8e2a5c586586ae9dc01fd634ea977e2714fbef62d7626eb3fb"
      id = "0b18a4a3-82da-574b-8d10-daf2176448b9"
   strings:
      $x1 = "process call create \"cmd.exe /c schtasks /Create /F /RU System /SC ONLOGON " ascii fullword
      $x2 = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCn7fL/1qsWkJkUtXKZIJNqYfnVByVhK" ascii fullword
      
      $s1 = "process call create \"cmd.exe /c schtasks /Create /F " ascii fullword
      $s2 = "twr.ini" ascii fullword
      $s3 = "/c wmic /node:'" ascii fullword

      $op1 = { 0f 4f d9 81 ff dc 0f 00 00 5f 8d 4b 0? 0f 4e cb 83 fe 3c 5e 5b }
      $op2 = { 6a 02 e8 ?? ?? 0? 00 83 c4 18 83 f8 01 75 01 cc 6a 00 68 ?? ?? 00 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 4000KB and (
         1 of ($x*) or 
         all of ($op*) 
         or 3 of them
      ) 
}