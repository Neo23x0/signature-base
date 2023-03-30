import "pe"

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_2 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dan__mayer/status/1641170769194672128?s=20"
      date = "2023-03-29"
      score = 80
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
   strings:
      $s1 = "raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
      $s2 = "https://raw.githubusercontent.com/IconStorages" wide fullword
      $s3 = "icon%d.ico" wide fullword
      $s4 = "__tutmc" ascii fullword

      $op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 }
      $op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 }
      $op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 900KB and 3 of them
      or 5 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise"
      author = "X__Junior, Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 85
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
    strings:
      $op1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 } /* VirtualProtect and execute payload*/
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00} /* ReadFile and MZ compare*/
      $op3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE} /* marker */
      $op4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1} /* xor part in RC4 decryption*/
    condition:
      uint16(0) == 0x5a4d
      and filesize < 3MB 
      and pe.characteristics & pe.DLL
      and 2 of them
}

rule SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects marker found in malicious DLLs related to 3CX compromise"
      author = "X__Junior, Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 75
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
   strings:
      $opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE } 
   condition:
      $opx1
}

rule APT_SUSP_NK_3CX_RC4_Key_Mar23_1 {
   meta:
      description = "Detects RC4 key used in 3CX binaries known to be malicious"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 70
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
      hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
   strings:
      $x1 = "3jB(2bsG#@c7"
   condition:
      ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d )
      and $x1
}

rule SUSP_3CX_App_Signed_Binary_Mar23_1 {
   meta:
      description = "Detects 3CX application binaries signed with a certificate and created in a time frame in which other known malicious binaries have been created"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 65
      hash1 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
      hash2 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"
   strings:
      $sa1 = "3CX Ltd1"
      $sa2 = "3CX Desktop App" wide
      $sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 } // Known compromised cert
   condition:
      uint16(0) == 0x5a4d
      and pe.timestamp > 1669680000 // 29.11.2022 earliest known malicious sample 
      and pe.timestamp < 1680108505 // 29.03.2023 date of the report
      and all of ($sa*)
      and $sc1 // serial number of known compromised certificate
}

rule SUSP_3CX_MSI_Signed_Binary_Mar23_1 {
   meta:
      description = "Detects 3CX MSI installers signed with a known compromised certificate and signed in a time frame in which other known malicious binaries have been signed"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 60
      hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
   strings:
      $a1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 } // MSI marker

      $sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 } // Known compromised cert

      $s1 = "3CX Ltd1"
      $s2 = "202303" // in 
   condition:
      uint16(0) == 0xcfd0
      and $a1 
      and $sc1 
      and (
         $s1 in (filesize-20000..filesize)
         and $s2 in (filesize-20000..filesize)
      )
}

