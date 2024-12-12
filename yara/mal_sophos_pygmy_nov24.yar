
rule MAL_Sophos_XG_Pygmy_Goat_AES_Key {
   meta:
      description = "Detects Pygmy Goat - a native x86-32 ELF shared object that was discovered on Sophos XG firewall devices, providing backdoor access to the device. This detection rule is based on the Pygmy Goat AES key built on the stack or in data"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "62be3f4f-b435-54b2-b596-4ad01606edb8"
   strings:
      $dword_1 = { 59 4b 6e 77 }
      $dword_2 = { 51 6a 6d 41 }
      $dword_3 = { 54 62 41 6e }
      $dword_4 = { 52 6f 5a 6d }
      $dword_5 = { 30 66 47 37 }
      $dword_6 = { 55 5a 57 62 }
      $dword_7 = { 32 59 55 78 }
      $dword_8 = { 55 51 50 77 }
   condition:
      uint32(0) == 0x464c457f and all of them
      // due to FPs - but I don't know the file size of the implant 
      and filesize < 4MB
}

rule MAL_Sophos_XG_Pygmy_Goat_Magic_Strings {
   meta:
      description = "Detects Pygmy Goat - a native x86-32 ELF shared object that was discovered on Sophos XG firewall devices, providing backdoor access to the device. This detection rule is based on the magic byte sequences used in C2 communications."
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "7df6c228-d569-5f1c-8bbb-4194347f99d1"
   strings:
      $c2_magic_handshake = ",bEB3?=o"
      $fake_ssh_banner = "SSH-2.0-D8pjE"
      $fake_ed25519_key = { 29 cc f0 cc 16 c5 46 6e 52 19 82 8e 86
      65 42 8c 1f 1a d4 c3 a5 b1 cb fc c0 26 6c 31 3c 5c 90 3a 24 7d e4 d3 57
      6d da 8e cb f4 66 d1 cb 81 4f 63 fd 4a fa 06 e4 7e 4c a0 95 91 bd cb 97
      a4 b3 0f }
   condition:
      uint32(0) == 0x464c457f and any of them
}

rule MAL_EarthWorm_Socks_Proxy_ID_Generation {
   meta:
      description = "Detects EarthWorm - a reverse socks proxy used by the threat group that deployed Pygmy Goat malware on Sophos XG firewall devices. The detection is based on the pool num generation x86 assembly."
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "242777e4-3abb-50d8-8c45-746cc4a8b1f8"
   strings:
      $chartoi = {
         8b 45 ?? // MOV EAX,dword ptr [EBP + ??]
         c1 e0 07 // SHL EAX,0x7
         89 c1 // MOV ECX,EAX
         8b 55 ?? // MOV EDX,dword ptr [EBP + ??]
         8b 45 ?? // MOV EAX,dword ptr [EBP + ??]
         01 d0 // ADD EAX,EDX
         0f b6 00 // MOVZX EAX,byte ptr [EAX]
         0f be c0 // MOVSX EAX,AL
         01 c8 // ADD EAX,ECX
         89 45 ?? // MOV dword ptr [EBP + ??],EAX
         83 6d ?? 01 // SUB dword ptr [EBP + ??],0x1
      }
   condition:
      uint32(0) == 0x464c457f and all of them
}
