import "pe"
rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      score = 85
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      id = "74c403ea-3178-58e8-88b3-a51c1d475868"
    strings:
      $op1 = {B8 AB AA AA AA F7 E1 8B C1 C1 EA 02 8D 14 52 03 D2 2B C2 8A 84 05 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ??} /* xor decryption*/ 
      $op2 = { 50 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 3C 00 00 00 C7 85 ?? ?? ?? ?? 40 00 00 00 C7 85 ?? ?? ?? ?? 05 00 00 00 FF 15} /* shellexecute*/
      $op3 = { 6A 00 8D 85 ?? ?? ?? ?? 50 6A 04 8D 85 ?? ?? ?? ?? 50 57 FF 15 } /* read file*/
    condition:
      uint16(0) == 0x5a4d and all of them
}

rule SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 {
   meta:
      description = "Detects marker found in VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      modified = "2023-04-21"
      score = 75
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      id = "8f0d92b6-d9b0-55e3-b2ca-601d095f5279"
   strings:
      $opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76} /* marker */
      $opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF} /* 1st xor key*/
      $opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF } /* 2nd xor key*/
   condition:
      2 of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_1 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "404b09def6054a281b41d309d809a428"
      hash2 = "c6441c961dcad0fe127514a918eaabd4"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "3e7c92fe-a7bd-5180-9935-4f98f2b64e2b"
   strings:
      $rh1 = { 68 5D 7A D2 2C 3C 14 81 2C 3C 14 81 2C 3C 14 81 77 54 10 80 26 3C 14 81 77 54 17 80 29 3C 14 81 77 54 11 80 AB 3C 14 81 D4 4C 11 80 33 3C 14 81 D4 4C 10 80 22 3C 14 81 D4 4C 17 80 25 3C 14 81 77 54 15 80 27 3C 14 81 2C 3C 15 81 4B 3C 14 81 94 4D 1D 80 28 3C 14 81 94 4D 14 80 2D 3C 14 81 94 4D 16 80 2D 3C 14 81 }
      $rh2 = { 00 E5 A0 2B 44 84 CE 78 44 84 CE 78 44 84 CE 78 1F EC CA 79 49 84 CE 78 1F EC CD 79 41 84 CE 78 1F EC CB 79 C8 84 CE 78 BC F4 CA 79 4A 84 CE 78 BC F4 CD 79 4D 84 CE 78 BC F4 CB 79 65 84 CE 78 1F EC CF 79 43 84 CE 78 44 84 CF 78 22 84 CE 78 FC F5 C7 79 42 84 CE 78 FC F5 CE 79 45 84 CE 78 FC F5 CC 79 45 84 CE 78}
      $rh3 = { DA D2 21 22 9E B3 4F 71 9E B3 4F 71 9E B3 4F 71 C5 DB 4C 70 94 B3 4F 71 C5 DB 4A 70 15 B3 4F 71 C5 DB 4B 70 8C B3 4F 71 66 C3 4B 70 8C B3 4F 71 66 C3 4C 70 8F B3 4F 71 C5 DB 49 70 9F B3 4F 71 66 C3 4A 70 B0 B3 4F 71 C5 DB 4E 70 97 B3 4F 71 9E B3 4E 71 F9 B3 4F 71 26 C2 46 70 9F B3 4F 71 26 C2 B0 71 9F B3 4F 71 9E B3 D8 71 9F B3 4F 71 26 C2 4D 70 9F B3 4F 71 }
      $rh4 = { CB 8A 35 66 8F EB 5B 35 8F EB 5B 35 8F EB 5B 35 D4 83 5F 34 85 EB 5B 35 D4 83 58 34 8A EB 5B 35 D4 83 5E 34 09 EB 5B 35 77 9B 5E 34 92 EB 5B 35 77 9B 5F 34 81 EB 5B 35 77 9B 58 34 86 EB 5B 35 D4 83 5A 34 8C EB 5B 35 8F EB 5A 35 D3 EB 5B 35 37 9A 52 34 8C EB 5B 35 37 9A 58 34 8E EB 5B 35 37 9A 5B 34 8E EB 5B 35 37 9A 59 34 8E EB 5B 35 }
   condition:
      uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($rh*)
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_2 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "404b09def6054a281b41d309d809a428"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "1b96c2f0-1c57-593e-9630-a72d43eb857e"
   strings:
      $sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }
      $si1 = "CryptBinaryToStringA" fullword
      $si2 = "BCryptGenerateSymmetricKey" fullword
      $si3 = "CreateThread" fullword
      $ss1 = "ChainingModeGCM" wide
      $ss2 = "__tutma" fullword
   condition:
      (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_3 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      md5 = "c6441c961dcad0fe127514a918eaabd4"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "82790c65-1d93-509b-95df-841543943c30"
   strings:
      $ss1 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 2C 20 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 2C 20 2A 2F 2A 3B 20 71 3D 30 2E 30 31 00 00 61 63 63 65 70 74 00 00 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 39 00 00 61 63 63 65 70 74 2D 6C 61 6E 67 75 61 67 65 00 63 6F 6F 6B 69 65 00 00 }
      $si1 = "HttpSendRequestW" fullword
      $si2 = "CreateNamedPipeW" fullword
      $si3 = "CreateThread" fullword
      $se1 = "DllGetClassObject" fullword
   condition:
      (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_4 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "404b09def6054a281b41d309d809a428" 
      hash2 = "c6441c961dcad0fe127514a918eaabd4"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "379e6471-3c4f-5c72-b8fd-17f481e89ac6"
   strings:
      $sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }
      $sb2 = { 33 D2 33 C9 FF 15 [4] 4C 8B CB 4C 89 74 24 28 4C 8D 05 [2] FF FF 44 89 74 24 20 33 D2 33 C9 FF 15 }
      $si1 = "CreateThread" fullword
      $si2 = "MultiByteToWideChar" fullword
      $si3 = "LocalAlloc" fullword
      $se1 = "DllGetClassObject" fullword
   condition:
      (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_5 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "6727284586ecf528240be21bb6e97f88"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "7d0718fc-4f1c-5293-8dc4-81a5783fbfb2"
   strings:
      $sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }
      $ss1 = "chrome.exe" wide fullword
      $ss2 = "firefox.exe" wide fullword
      $ss3 = "msedge.exe" wide fullword
      $ss4 = "\\\\.\\pipe\\*" ascii fullword
      $ss5 = "FindFirstFileA" ascii fullword
      $ss6 = "Process32FirstW" ascii fullword
      $ss7 = "RtlAdjustPrivilege" ascii fullword
      $ss8 = "GetCurrentProcess" ascii fullword
      $ss9 = "NtWaitForSingleObject" ascii fullword
   condition:
      (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_6 {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      score = 75
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "00a43d64f9b5187a1e1f922b99b09b77"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "2cbedbc0-d465-5674-bf9c-9362003eb8d2"
   strings:
      $ss1 = "C:\\Programdata\\" wide
      $ss2 = "devobj.dll" wide fullword
      $ss3 = "msvcr100.dll" wide fullword
      $ss4 = "TpmVscMgrSvr.exe" wide fullword
      $ss5 = "\\Microsoft\\Windows\\TPM" wide fullword
      $ss6 = "CreateFileW" ascii fullword
   condition:
      (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule SUSP_NK_MAL_M_Hunting_POOLRAT {
   meta:
      description = "Detects VEILEDSIGNAL malware"
      author = "Mandiant"
      old_rule_name = "APT_NK_MAL_M_Hunting_POOLRAT"
      score = 70
      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
      description = "Detects strings found in POOLRAT malware"
      hash1 = "451c23709ecd5a8461ad060f6346930c"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "70f5f3a0-0fd0-54dc-97cc-4f3c35f02fcd"
   strings:
      /*
      $hex1 = { 6e 61 6d 65 3d 22 75 69 64 22 25 73 25 73 25 75 25 73 }
      $hex_uni1 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 69 00 64 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }
      */
      $s1 = "name=\"uid\"%s%s%u%s" ascii wide
      /*
      $hex2 = { 6e 61 6d 65 3d 22 73 65 73 73 69 6f 6e 22 25 73 25 73 25 75 25 73 }
      $hex_uni2 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }
      */
      $s2 = "name=\"session\"%s%s%u%s" ascii wide
      /*
      $hex3 = { 6e 61 6d 65 3d 22 61 63 74 69 6f 6e 22 25 73 25 73 25 73 25 73 }
      $hex_uni3 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 61 00 63 00 74 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 }
      */
      $s3 = "name=\"action\"%s%s%s%s" ascii wide
      /*
      $hex4 = { 6e 61 6d 65 3d 22 74 6f 6b 65 6e 22 25 73 25 73 25 75 25 73 }
      $hex_uni4 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 74 00 6f 00 6b 00 65 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }
      */
      $s4 = "name=\"token\"%s%s%u%s" ascii wide
      $str1 = "--N9dLfqxHNUUw8qaUPqggVTpX-" wide ascii nocase
   condition:
      any of ($s*) or $str1
}

rule APT_NK_TradingTech_ForensicArtifacts_Apr23_1 {
   meta:
      description = "Detects forensic artifacts, file names and keywords related the Trading Technologies compromise UNC4736"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      modified = "2023-04-21"
      score = 60
      id = "f79a5321-4f22-52d9-aa83-4aa750ecc036"
   strings:
      $x1 = "www.tradingtechnologies.com/trading/order-management" ascii wide
      
      $xf1 = "X_TRADER_r7.17.90p608.exe" ascii wide
      $xf2 = "\\X_TRADER-ja.mst" ascii wide
      $xf3 = "C:\\Programdata\\TPM\\TpmVscMgrSvr.exe" ascii wide
      $xf4 = "C:\\Programdata\\TPM\\winscard.dll" ascii wide

      $fp1 = "<html"
   condition:
      not uint16(0) == 0x5025
      and 1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_TH_APT_UNC4736_TradingTech_Cert_Apr23_1 {
   meta:
      description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      score = 65
      id = "9a05fba9-9466-5b69-9207-27ad01d6eb8b"
   strings:
      $s1 = { 00 85 38 A6 C5 01 8F 50 FC } /* serial number */
      $s2 = "Go Daddy Secure Certificate Authority - G2" /* CA */
      $s3 = "Trading Technologies International, Inc"
   condition:
      pe.timestamp > 1651363200 /* Sunday, May 1, 2022 12:00:00 AM */
      and all of them
}
