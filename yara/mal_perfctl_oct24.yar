
rule MAL_EXPL_Perfctl_Oct24 {
   meta:
      description = "Detects exploits used in relation with Perfctl malware campaigns"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09"
      score = 80
      hash1 = "22e4a57ac560ebe1eff8957906589f4dd5934ee555ebcc0f7ba613b07fad2c13"
      id = "1f525eaf-445c-592e-bfa4-e9846390dd1d"
   strings:
      $s1 = "Exploit failed. Target is most likely patched." ascii fullword
      $s2 = "SHELL=pkexec" ascii fullword
      $s3 = "/dump_" ascii fullword
      $s4 = ".EYE$" ascii
   condition:
      uint16(0) == 0x457f
      and filesize < 30000KB
      and 2 of them
      or all of them
}

rule MAL_LNX_Perfctl_Oct24 {
   meta:
      description = "Detects Perfctl malware samples"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09"
      score = 75
      hash1 = "a6d3c6b6359ae660d855f978057aab1115b418ed277bb9047cd488f9c7850747"
      hash2 = "ca3f246d635bfa560f6c839111be554a14735513e90b3e6784bedfe1930bdfd6"
      id = "391513ae-3348-5297-a22a-6f06e50f06d2"
   strings:
      $op1 = { 83 45 f8 01 8b 45 f8 48 3b 45 98 0f 82 1b ff ff ff 90 c9 c3 55 }
      $op2 = { 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f }
      $op3 = { 88 4c 10 58 83 45 f8 01 83 7d f8 03 0f 86 68 ff ff ff 90 c9 c3 55 }
      $op4 = { 48 83 ec 68 48 89 7d a8 48 89 75 a0 48 89 55 98 48 8b 45 a8 48 8b 00 83 e0 3f 89 45 fc }
   condition:
      uint16(0) == 0x457f
      and filesize < 300KB
      and 2 of them
}
