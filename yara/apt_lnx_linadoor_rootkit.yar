
rule MAL_LNX_LinaDoor_Rootkit_May22 {
   meta:
      description = "Detects LinaDoor Linux Rootkit"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2022-05-19"
      modified = "2023-05-16"
      score = 85
      hash1 = "25ff1efe36eb15f8e19411886217d4c9ec30b42dca072b1bf22f041a04049cd9"
      hash2 = "4792e22d4c9996af1cb58ed54fee921a7a9fdd19f7a5e7f268b6793cdd1ab4e7"
      hash3 = "9067230a0be61347c0cf5c676580fc4f7c8580fc87c932078ad0c3f425300fb7"
      hash4 = "940b79dc25d1988dabd643e879d18e5e47e25d0bb61c1f382f9c7a6c545bfcff"
      hash5 = "a1df5b7e4181c8c1c39de976bbf6601a91cde23134deda25703bc6d9cb499044"
      hash6 = "c4eea99658cd82d48aaddaec4781ce0c893de42b33376b6c60a949008a3efb27"
      hash7 = "c5651add0c7db3bbfe0bbffe4eafe9cd5aa254d99be7e3404a2054d6e07d20e7"
      id = "e2f250b4-9a8a-5d70-83d7-5d12ad3763fb"
   strings:
      $s1 = "/dev/net/.../rootkit_/" ascii
      $s2 = "did_exec" ascii fullword
      $s3 = "rh_reserved_tp_target" ascii fullword
      $s4 = "HIDDEN_SERVICES" ascii fullword
      $s5 = "bypass_udp_ports" ascii fullword
      $s6 = "DoBypassIP" ascii fullword

      $op1 = { 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 }
      $op2 = { e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b }
      $op3 = { 48 89 c3 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 }
      $op4 = { 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b 41 5c 41 5d }

      $fp1 = "/wgsyncdaemon.pid"
   condition:
      uint16(0) == 0x457f and
      filesize < 2000KB and 2 of them 
      and not 1 of ($fp*)
      or 4 of them
}
