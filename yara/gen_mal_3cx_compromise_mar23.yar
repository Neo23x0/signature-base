import "pe"

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

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_3 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth , X__Junior"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 80
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
    strings:
      $opa1 = { 41 81 C0 ?? ?? ?? ?? 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1 41 69 D0 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 ?? ?? ?? ?? 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 } /*lcg chunk */
      $opa2 = { 8B C8 41 69 D1 ?? ?? ?? ?? C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 4C 0F AF CF 44 69 C2 ?? ?? ?? ?? 4C 03 C9 45 8B D1 4C 0F AF D7} /*lcg chunk */

      $opb1 = { 45 33 C9 48 89 6C 24 ?? 48 8D 44 24 ?? 48 89 6C 24 ?? 8B D3 48 89 B4 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 ?? FF 15 } /* base64 decode */
      $opb2 = { 44 8B 0F 45 8B C6 48 8B 4D ?? 49 8B D7 44 89 64 24 ?? 48 89 7C 24 ?? 44 89 4C 24 ?? 4C 8D 4D ?? 48 89 44 24 ?? 44 89 64 24 ?? 4C 89 64 24 ?? FF 15} /* AES decryption */
      $opb3 = { 48 FF C2 66 44 39 2C 56 75 ?? 4C 8D 4C 24 ?? 45 33 C0 48 8B CE FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 44 0F B7 44 24 ?? 33 F6 48 8B 54 24 ?? 45 33 C9 48 8B 0B 48 89 74 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 74 24 ?? FF 15 } /* internet connection */
      $opb4 = { 33 C0 48 8D 6B ?? 4C 8D 4C 24 ?? 89 44 24 ?? BA ?? ?? ?? ?? 48 89 44 24 ?? 48 8B CD 89 44 24 ?? 44 8D 40 ?? 8B F8 FF 15} /* VirtualProtect */
    condition:
      ( all of ($opa*) )
      or
      ( 1 of ($opa*) and 1 of ($opb*) )
      or
      ( 3 of ($opb*) )
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

rule APT_MAL_macOS_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-30"
      score = 80
      hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
      hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
      hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
    strings:
      $s1 = "20230313064152Z0"
      $s2 = "Developer ID Application: 3CX (33CF4654HL)"
    condition:
      uint16(0) == 0xfeca and all of them
}

/* 30.03.2023 */

rule APT_MAL_MacOS_NK_3CX_DYLIB_Mar23_1 {
   meta:
      description = "Detects malicious DYLIB files related to 3CX compromise"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
      date = "2023-03-30"
      score = 80
      hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
      hash2 = "fee4f9dabc094df24d83ec1a8c4e4ff573e5d9973caa676f58086c99561382d7"
   strings:
      /* XORed UA 0x7a */
      $xc1 = { 37 15 00 13 16 16 1B 55 4F 54 4A 5A 52 2D 13 14 
               1E 15 0D 09 5A 34 2E 5A 4B 4A 54 4A 41 5A 2D 13
               14 4C 4E 41 5A 02 4C 4E 53 5A 3B 0A 0A 16 1F 2D
               1F 18 31 13 0E 55 4F 49 4D 54 49 4C 5A 52 31 32
               2E 37 36 56 5A 16 13 11 1F 5A 3D 1F 19 11 15 53
               5A 39 12 08 15 17 1F 55 4B 4A 42 54 4A 54 4F 49
               4F 43 54 4B 48 42 5A 29 1B 1C 1B 08 13 55 4F 49
               4D 54 49 4C 7A }
      /* /;3cx_auth_token_content=%s;__tutma= */
      $xc2 = { 41 49 19 02 25 1b 0f 0e 12 25 0e 15 11 1f 14 25 19 15 14 0e 1f 14 0e 47 5f 09 41 25 25 0e 0f 0e 17 1b 47 }
      /* /System/Library/CoreServices/SystemVersion.plist */
      $xc3 = { 55 29 03 09 0e 1f 17 55 36 13 18 08 1b 08 03 55 39 15 08 1f 29 1f 08 0c 13 19 1f 09 55 29 03 09 0e 1f 17 2c 1f 08 09 13 15 14 54 0a 16 13 09 0e }
   condition:
      1 of them
}

rule APT_SUSP_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects indicator (event name) found in samples related to 3CX compromise"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
      date = "2023-03-30"
      score = 70
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
      hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
   strings:
      $a1 = "AVMonitorRefreshEvent" wide fullword
   condition:
      1 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_4 {
    meta:
        author = "MalGamy"
        reference = "https://twitter.com/WhichbufferArda/status/1641404343323688964?s=20"
        description = "Detects decrypted payload loaded inside 3CXDesktopApp.exe which downloads info stealer"
        date = "2023-03-29"
        hash = "851c2c99ebafd4e5e9e140cfe3f2d03533846ca16f8151ae8ee0e83c692884b7" 
        score = 80
    strings:
        $op1 = {41 69 D0 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 [4] 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 [4] 33 C1 4C 0F AF CF 4D 03 CA 45 8B D1 4C 0F AF D7 41 8D 0C 11 49 C1 E9 ?? 02 C8} // // xor with mul operation
        $op2 = {4D 0F AF CC 44 69 C2 [4] 4C 03 C9 45 8B D1 4D 0F AF D4 41 8D 0C 11 41 81 C0 [4] 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1} // xor with mul operation
        $op3 = {33 C1 4C 0F AF C7 8B C8 C1 E1 ?? 4D 03 C2 33 C1} // shift operation
    condition: 
        2 of them
}

rule MAL_3CXDesktopApp_MacOS_Backdoor_Mar23 {
    meta:
      author = "X__Junior"
        reference = "https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/"
        description = "Detects 3CXDesktopApp MacOS Backdoor component"
        date = "2023-03-30"
        hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
        score = 80
    strings:
        $sa1 = "%s/.main_storage" ascii fullword
        $sa2 = "%s/UpdateAgent" ascii fullword

        $op1 = { 31 C0 41 80 34 06 ?? 48 FF C0 48 83 F8 ?? 75 ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 F7 48 89 D9 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 F7 5B 41 5E 41 5F E9 ?? ?? ?? ?? 5B 41 5E 41 5F C3} /* string decryption */
        $op2 = { 0F 11 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 31 C0 80 B4 04 ?? ?? ?? ?? ?? 48 FF C0} /* string decryption */
    condition:
      ( uint16(0) == 0xfeca and filesize < 6MB
         and
         (
            ( 1 of ($sa*) and 1 of ($op* ) )
            or all of ($sa*)
         )
      )
      or ( all of ($op*) )
}
