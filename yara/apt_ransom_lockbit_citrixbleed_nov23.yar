rule MAL_Backdoor_DLL_Nov23_1 {
   meta:
      author = "X__Junior"
      description = "Detects a backdoor DLL, that was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "cc21c77e1ee7e916c9c48194fad083b2d4b2023df703e544ffb2d6a0bfc90a63"
      hash2 = "0eb66eebb9b4d671f759fb2e8b239e8a6ab193a732da8583e6e8721a2670a96d"
      score = 80
      id = "3588d437-b561-5380-8dac-73a31f4cdb5a"
   strings:
      $s1 = "ERROR GET INTERVAL" ascii
      $s2 = "OFF HIDDEN MODE" ascii
      $s3 = "commandMod:" ascii
      $s4 = "RESULT:" ascii

      $op1 = { C7 44 24 ?? 01 00 00 00 C7 84 24 ?? ?? ?? ?? FF FF FF FF 83 7C 24 ?? 00 74 ?? 83 BC 24 ?? ?? ?? ?? 00 74 ?? 4C 8D 8C 24 ?? ?? ?? ?? 41 B8 00 04 00 00 48 8D 94 24 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 }
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 03 00 00 00 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 44 0F B7 05 ?? ?? ?? ?? 48 8B D0 48 8B 4C 24 ?? FF 15 }
   condition:
      uint16(0) == 0x5a4d
      and ( all of ($s*) or all of ($op*) )
}

rule MAL_Trojan_DLL_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
      score = 80
      id = "1dd87d0a-2b8b-5386-8fdd-40d184c731a4"
   strings:
      $op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 }
      $op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 }
      $op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D }
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MAL_DLL_Stealer_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
      score = 80
      id = "9cfed8ec-1d04-53d7-88ef-2576075cfc33"
   strings:
      $op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00}
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MAL_Python_Backdoor_Script_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
      score = 80
      id = "861f9ce3-3c54-5c56-b50b-2b7536783f6e"
   strings:
      $s1 = "port = 443 if \"https\"" ascii
      $s2 = "winrm.Session basic error" ascii
      $s3 = "Windwoscmd.run_cmd(str(cmd))" ascii
   condition:
      filesize < 50KB and all of them
}

rule APT_RANSOM_Lockbit_ForensicArtifacts_Nov23 {
   meta:
      description = "Detects patterns found in Lockbit TA attacks exploiting Citrixbleed vulnerability CVE 2023-4966"
      author = "Florian Roth"
      date = "2023-11-22"
      score = 75
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      id = "04bde599-2a5b-5a33-a6f1-67d57a564946"
   strings:
      $x1 = "taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe"
      $x2 = " 1> \\\\127.0.0.1\\admin$\\__"
   condition:
      1 of ($x*)
}
