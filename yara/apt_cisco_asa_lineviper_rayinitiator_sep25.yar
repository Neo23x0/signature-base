rule MAL_Cisco_RayInitiator_Stage_1 {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 1 code that searches for the 'Booting the kernel' string."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         BB 00 00 40 00 43 81 FB 00 00 60 00 0F 87 AB 00 00 00
         8B 3B 81 FF 64 6F 6E 65 75 E9 83 C3 04 8B 3B 81 FF 2E 0A 42 6F 75
         DC 83 C3 04 8B 3B 81 FF 6F 74 69 6E 75 CF 83 C3 04 8B 3B 81 FF 67
         20 74 68 75 C2 83 C3 04 8B 3B 81 FF 65 20 6B 65 75 B5 83 C3 04 8B
         3B 81 FF 72 6E 65 6C 75 A8 83 EB 14
      }
   condition:
      $xc1
}

rule MAL_Cisco_RayInitiator_Stage_2 {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 2 code that identifies the Linux kernel syscall table."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         49 89 E0 48 83 F8 30 0F 84 70 00 00 00 49 01 C0 49 8B
         10 48 83 C0 08 66 85 D2 75 E4 BF ?? ?? 60 00 48 8B 3C 17 48 BE 6E
         6D 69 5F 6D 61 78 5F
      }
   condition:
      $xc1
}

rule MAL_Cisco_RayInitiator_Stage_3 {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 3 install phase code that searches for the 'client-cert-fail' string."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 81 EE 00 00 00 08 48 B8 63 6C 69 65 6E 74 2D 63 49
         B8 65 72 74 2D 66 61 69 6C 48 FF C6 48 39 D6 0F 87 D2
         00 00 00 48 8B 3E 48 39 C7
      }
   condition:
      $xc1
}

rule MAL_Cisco_RayInitiator_Stage_3_LINE_VIPER_ShellCode {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 3 deploy phase code that copies LINE VIPER shellcode stub and marks executable."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
   strings:
      $xc1 = {
         48 89 FA 48 83 C7 40 4C 89 CE B9 D0 01 00 00 F3 A4 48
         89 D7 48 83 C7 40 48 89 3A 48 C1 EF 0C 48 C1 E7 0C BA
         07 00 00 00 48 C7 C6 00 20 00 00
      }
   condition:
      $xc1
}

rule MAL_Cisco_LINE_VIPER_Shellcode_Deobfuscation_Routine {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of a shellcode deobfuscation routine."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 8B 7F 08 48 8D 5F 70 49 C7 C1 00 18 00 00 49 C7 C0
         20 00 00 00 48 89 DF 8A 01 32 07 48 FF C7 41 FF C8 4D 85 C0 75 F3
         88 01 48 FF C1 41 FF C9 4D 85 C9 75 DA
      }
      $x1 = "SIt/CEiNX3BJx8EAGAAAScfAIAAAAEiJ34oBMgdI/8dB/8hNhcB184gBSP/BQf/JTYXJdd"
      $x2 = "iLfwhIjV9wScfBABgAAEnHwCAAAABIid+KATIHSP/HQf/ITYXAdfOIAUj/wUH/yU2FyXXa"
      $x3 = "Ii38ISI1fcEnHwQAYAABJx8AgAAAASInfigEyB0j/x0H/yE2FwHXziAFI/8FB/8lNhcl12"
   condition:
      1 of them
}

rule MAL_Cisco_LINE_VIPER_Shellcode_Initial_Execution {
   meta:
      author = "NCSC (modifier by Florian Roth)"
      description = "Detects LINE VIPER Cisco ASA malware code as part of shellcode initial execution."
      date = "2025-09-25"
      modified = "2025-09-27"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 8D B7 80 00 00 00 BA 00 20 00 00 [19] 48 C7 C6 00
         90 00 00 BA 07 00 00 00
      }
      // $x1 = /SI23gAAAALoAIAAA[A-Za-z0-9+\/]{26}jHxgCQAAC6BwAAA/
      // $x2 = /iNt4AAAAC6ACAAA[A-Za-z0-9+\/]{26}Ix8YAkAAAugcAAA/
      // $x3 = /IjbeAAAAAugAgAA[A-Za-z0-9+\/]{26}SMfGAJAAALoHAAAA/
      $xe1 = { 53 49 32 33 67 41 41 41 41 4c 6f 41 49 41 41 41 [26] 6a 48 78 67 43 51 41 41 43 36 42 77 41 41 41 }
      $xe2 = { 69 4e 74 34 41 41 41 41 43 36 41 43 41 41 41 [26] 49 78 38 59 41 6b 41 41 41 75 67 63 41 41 41 }
      $xe3 = { 49 6a 62 65 41 41 41 41 41 75 67 41 67 41 41 [26] 53 4d 66 47 41 4a 41 41 41 4c 6f 48 41 41 41 41 }
   condition:
      1 of them
}

rule MAL_Cisco_LINE_VIPER_RSA_Enc_Random_AES_Key_Gen {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of RSA encrypted random AES key generation."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 31 C0 49 89 06 49 89 46 08 49 83 C6 10 49 83 ED 10
         4D 85 ED 75 D8 BF 30 00 00 00
      }
      $xc2 = {
         0F 85 57 01 00 00 49 8B 44 24 08 48 83 F8 2F 7C 33 41
         BD F0 02 00 00 4D 8D 74 24 10 49 8B 3E
      }
      $xc3 = {
         85 C0 0F 8E EE 00 00 00 41 BD F0 02 00 00 4D 8D 7C 24
         10 49 8B 3F 48 85 FF 74 0D 49 83 C7 10 49 83 ED 10 4D 85 ED 75 EB
         4D 89 37 BF 70 00 00 00
      }
      $xc4 = {
         48 85 C0 0F 84 3F 00 00 00 48 89 45 B0 BF 80 00 00 00
         4C 89 EE 48 89 C2 48 8B 4D A8 41 B8 01 00 00 00
      }
   condition:
      1 of them
}

rule MAL_Cisco_LINE_VIPER_AES_Enc_Tasking_Exfil {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of AES encrypted tasking and exfiltration."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $ = {
         48 31 C0 48 89 45 D8 49 89 FC 49 89 F5 49 89 D6 48 8B
         47 08 48 89 45 B8 48 8D 40 40 48 89 45 E0 48 8D 70 E0 48 89 75 B0
         48 8D 78 F0 48 89 7D E8 BA 10 00 00 00
      }
      $ = {
         48 85 C0 0F 84 EA 00 00 00 48 89 45 A8 4C 89 EF 48 89
         C6 4C 89 F2 48 8B 4D A0 4C 8B 45 B0 4D 31 C9
      }
      $ = {
         48 85 C0 0F 84 82 00 00 00 49 89 C7 48 8B 7D E0 BE 00
         01 00 00 48 8B 55 A0
      }
      $ = {
         48 8B 7D D0 49 83 C7 10 49 C1 EF 04 49 C1 E7 04 4C 89
         FE 48 8D 55 D8
      }
   condition:
      3 of them
}

rule MAL_Cisco_LINE_VIPER_ICMP_Tasking_Shellcode_Payloads {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of ICMP tasking shellcode payloads."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $ = {
         55 53 41 54 41 55 41 56 41 57 48 89 E5 48 83 EC 60 48
         31 C0 B9 07 00 00 00 48 8D 7D A8 F3 48 AB BF 01 00 00
         00 BE 30 00 00 00
      }
      $ = {
         49 89 C7 48 C7 C2 38 DF FF FF 64 48 8B 0A 48 8B 99 00
         01 00 00 48 89 81 00 01 00 00
      }
      $ = {
         49 8B 47 10 48 8D 55 B0 BE 01 20 01 00 4C 89 FF FF 90
         90 00 00 00 48 8B 7D B0 48 85 FF 0F 84 3C 00 00 00
      }
      $ = {
         49 8B 47 10 BE 08 20 01 00 4C 89 FF 48 8D 55 A8 FF 90
         90 00 00 00 48 8B 7D B0 49 89 7E 20 48 8B 7D A8 49 89
         7E 28
      }
   condition:
      3 of them
}
