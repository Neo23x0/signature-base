
rule APT_PS1_SysAid_EXPL_ForensicArtifacts_Nov23_1 : SCRIPT {
   meta:
      description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
      author = "Florian Roth"
      score = 85
      reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
      date = "2023-11-09"
      id = "df7997d3-9309-58b3-8cd7-de9fea36d3c7"
   strings:
      $x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
      $x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide
   condition:
      1 of them
}

rule MAL_Loader_TurtleLoader_Nov23 {
   meta:
      description = "Detects Tutle loader used in attacks against SysAid CVE-2023-47246"
      author = "Florian Roth"
      reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
      date = "2023-11-09"
      score = 85
      hash1 = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
      id = "c7b5d03d-52c4-59b4-ac69-55e532a21340"
   strings:
      $s1 = "No key in args!" ascii fullword
      $s2 = "Bad data file!" ascii fullword
      $s3 = "Data file loaded. Running..." ascii

      $op1 = { 48 8d 55 c8 4c 8d 3d ac 8f 00 00 45 33 c9 45 33 d2 4d 8b e7 44 21 0a 45 33 db 4c 8d 3d 16 ec ff ff }
      $op2 = { 48 d3 e8 0f b6 c8 49 03 cb 49 81 c3 00 01 00 00 45 33 8c 8f a0 e4 00 00 41 83 fa 04 7c c7 41 ff c0 }
      $op3 = { 48 83 c1 04 48 ff ca 89 41 1c 75 ef 03 f6 48 83 c3 20 48 ff cd 0f 85 77 ff ff ff }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB
      and 3 of them
}

rule MAL_Grace_Dec22 {
    meta:
      author = "X__Junior"
      reference = "https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/"
      description = "Detects Grace (aka FlawedGrace and GraceWire) RAT"
      date = "2022-12-13"
      hash1 = "a66df3454b8c13f1b92d8b2cf74f5bfcdedfbff41a5e4add62e15277d14dd169"
      hash2 = "e113a8df3c4845365f924bacf10c00bcc5e17587a204b640852dafca6db20404"
      score = 70
      id = "fc2214dc-f1e5-52d7-a9de-88709a03b04e"
    strings:
      $sa1 = "Grace finalized, no more library calls allowed." ascii
      $sa2 = "Socket forcibly closed due to no response to DISCONNECT signal from other side, worker id(%d)" ascii
      $sa3 = "AVWireCleanupThread" ascii
      $sa4 = "AVTunnelClientDirectIO" ascii
      $sa5 = "AVGraceTunnelWriteThread" ascii
      $sa6 = "AVGraceTunnelClientDirectIO" ascii
    condition:
      2 of them
}
