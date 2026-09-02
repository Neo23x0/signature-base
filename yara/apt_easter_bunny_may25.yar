rule APT_MAL_RU_EasterBunny_Wrapper_May24 {
   meta:
      description = "Detects a wrapper used by the Easter Bunny APT group to execute in-memory implants. The wrapper is used to execute a command that includes a ping command followed by a del command, which is specific to the malware's behavior."
      reference = "https://home.s2grupo.es/hubfs/Informe%20LAB52-%20EasterBunny_Complete.pdf"
      version = "1.0"
      author = "Eric C"
      team = "LAB52"
      company = "S2Grupo"
      status = "stable"
      date = "2024-05-10"
      filetype = "exe"
   strings:
      $time_loop1 = { 55 41 57 41 56 41 54 56 57 53 48 83 EC 20 48 8D 6C 24 20 45 89 C6 49 89 D4 89 CE FF 15 ?? ?? ?? 00 89 }
      $time_loop2 = { C3 89 D9 E8 ?? ?? ?? 00 4C 89 E1 44 89 F2 E8 8B 00 00 00 85 C0 74 6C FF 15 ?? ?? ?? 00 41 }
      $time_loop3 = { 89 C7 41 29 DF 69 C6 E8 03 00 00 69 CE 10 27 00 00 48 69 F1 1F 85 EB 51 48 C1 EE 25 89 C3 29 F3 01 C6 }
      $time_loop4 = { E8 ?? ?? 00 00 29 DE 31 FF 31 D2 F7 F6 89 D1 01 D9 31 D2 89 C8 41 F7 F7 89 C6 BB 01 00 00 }
      $set_error = { 89 07 80 00 00 48 FF 25 ?? ?? ?? 00 }

      $xor = { 0F B7 0F 4C 89 E2 E8 A5 01 00 00 88 03 48 83 C7 02 48 FF C3 48 FF CE 75 E7 4A 8B 4C 2D B0 4C 89 }
      $xor2 = {
         49 C7 C0 FF FF FF FF 31 C0 0F 1F 80 00 00 00 00 66 42 39 4C 42 02 74
         3D 66 42 39 4C 42 04 74 24 66 42 39 4C 42 06 74 21 66 42 39 4C 42 08 74 1E
         48 83 C0 04 49 83 C0 04 49 81 F8 FF 00 00 00 72 CF 31 C0 C3 48 83 C8 01 C3
         48 83 C8 02 C3 49 83 C0 04 4C 89 C0 C3
      }

      $get_block1 = {
         55 41 57 41 56 41 55 41 54 56 57 53 48 83 EC 28 48 8D 5C 24 20
         40 89 CE 4D 89 C7 41 89 D5 49 89 CC 44 89 E9 EB ?? ?? 00 00
      }
      $get_block2 = {
         49 89 07 45 8B 44 24 01 45 85 ED 0F 84 9C 00 00 00 41 8A 54
         24 06 88 10 BF 01 00 00 00 41 83 FD 03 72 4F BF 01 00 00 00
      }
      $get_block3 = {
         BA 02 00 00 00 66 2E 0F 1F 84 00 00 00 00 00 49 8B 0F 89 FB
         83 E0 03 83 FB 01 83 D2 00 85 FF 0F 95 C0 40 F6 C7 0F 0F 94 C3 20 C3
         0F B6 C3 8B 1C 02 48 63 DB
      }
      $get_block4 = {
         0F B6 5C 1C 05 89 FE FF C7 88 1C 31 8D 54 02 01 44 39 EA 72
         C5 45 85 C0 74 36 85 FF 74 32 31 F6 31 DB 0F 1F 84 00 00 00 00 00
         89 F2 F7 D2 83 E2 01 8D 04 1A 49 8B 0F 48 98 0F BE 04 01 88 04 31
         48 FF C6 4C 39 C6 73 08 8D 5C 1A 01 39 FB 72 DA 46 89 06 B8 01 00 00 00
         48 83 C4 28 5B 5F 5E 41 5C 41 5D 41 5E 41 5F 5D C3 CC
      }
      $sort_block = {
         4C 8B D9 48 28 D1 0F 82 9E 01 00 00 49 83 F8 08 72 61 F6 C1
         07 74 36 F6 C1 01 74 0B BA 04 0A 49 FF C8 88 01 48 FF C1 F6 C1 02 74 0F
         66 8B 04 0A 49 83 E8 02 66 89 01 48 83 C1 02 F6 C1 04 74 0D 8B 04 0A
         49 83 E8 04 89 01 48 83 C1 04 40 8B C8 49 C1 E9 05 75 51 4D 8B C8
         49 C1 E9 03 74 14 48 8B 04 0A 48 89 01 48 83 C1 08 49 FF C9 75 F0
         49 83 E0 07 4D 85 C0 75 08 49 8B C3 C3 0F 1F 40 00
      }
   condition:
      (
         $set_error
         and all of ($time_loop*)
      )
      or all of ($xor*)
      or (
         all of ($get_block*)
         and $sort_block
      )
}
