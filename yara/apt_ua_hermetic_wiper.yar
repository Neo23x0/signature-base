
rule APT_UA_Hermetic_Wiper_Feb22_1 {
   meta:
      description = "Detects Hermetic Wiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
      date = "2022-02-24"
      score = 75
      hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
      hash2 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
      hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
      hash4 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      id = "2cbe4a69-e31a-5f5f-ab1a-9d71d16fb30f"
   strings:
      $xc1 = { 00 5C 00 5C 00 2E 00 5C 00 50 00 68 00 79 00 73
               00 69 00 63 00 61 00 6C 00 44 00 72 00 69 00 76
               00 65 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 45 00 50 00 4D 00 4E 00 54 00 44 00 52 00 56
               00 5C 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 00 00 00 00 25 00 73 00 25 00 2E 00 32 00 73
               00 00 00 00 00 24 00 42 00 69 00 74 00 6D 00 61
               00 70 00 00 00 24 00 4C 00 6F 00 67 00 46 00 69
               00 6C 00 65 }
      $sc1 = { 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 00
               00 64 00 72 00 76 00 00 00 53 00 79 00 73 00 74
               00 65 00 6D 00 33 00 32 }

      $s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
      $s2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
      $s3 = "DRV_XP_X64" wide fullword
      $s4 = "%ws%.2ws" wide fullword

      $op1 = { 8b 7e 08 0f 57 c0 8b 46 0c 83 ef 01 66 0f 13 44 24 20 83 d8 00 89 44 24 18 0f 88 3b 01 00 00 }
      $op2 = { 13 fa 8b 55 f4 4e 3b f3 7f e6 8a 45 0f 01 4d f0 0f 57 c0 }
   condition:
      ( uint16(0) == 0x5a53 or uint16(0) == 0x5a4d ) and
      filesize < 400KB and ( 1 of ($x*) or 3 of them )
}

rule APT_UA_Hermetic_Wiper_Artefacts_Feb22_1 {
   meta:
      description = "Detects artefacts found in Hermetic Wiper malware related intrusions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
      date = "2022-02-25"
      score = 75
      id = "77f793c1-b02c-59c3-b3e4-75758f5b3b8d"
   strings:
      $sx1 = "/c powershell -c \"rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump" ascii wide
      $sx2 = "appdata\\local\\microsoft\\windows\\winupd.log" ascii wide
      $sx3 = "AppData\\Local\\Microsoft\\Windows\\Winupd.log" ascii wide
      $sx4 = "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp1" ascii wide
      $sx5 = "\\policydefinitions\\postgresql.exe" ascii wide

      $sx6 = "powershell -v 2 -exec bypass -File text.ps1" ascii wide
      $sx7 = "powershell -exec bypass gp.ps1" ascii wide
      $sx8 = "powershell -exec bypass -File link.ps1" ascii wide

      /* 16 is the prefix of an epoch timestamp that shouldn't change until the 14th of November 2023 */
      $sx9 = " 1> \\\\127.0.0.1\\ADMIN$\\__16" ascii wide
      
      $sa1 = "(New-Object System.Net.WebClient).DownloadFile(" ascii wide
      $sa2 = "CSIDL_SYSTEM_DRIVE\\temp\\" ascii wide
      $sa3 = "1> \\\\127.0.0.1\\ADMIN$" ascii wide

      $fp1 = "<html" ascii
   condition:
      1 of ($sx*) or all of ($sa*)
      and not 1 of ($fp*)
}

rule APT_UA_Hermetic_Wiper_Scheduled_Task_Feb22_1 {
   meta:
      description = "Detects scheduled task pattern found in Hermetic Wiper malware related intrusions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
      date = "2022-02-25"
      score = 85
      id = "a628f773-9c71-5979-a4db-37b6b6bd6a56"
   strings:
      $a0 = "<Task version=" ascii wide

      $sa1 = "CSIDL_SYSTEM_DRIVE\\temp" ascii wide
      $sa2 = "postgresql.exe 1> \\\\127.0.0.1\\ADMIN$" ascii wide
      $sa3 = "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE" ascii wide
   condition:
      $a0 and 1 of ($s*)
}
