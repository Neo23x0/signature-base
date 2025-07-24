rule MAL_Win_Amadey_Jun25 {
   meta:
      author = "0x0d4y"
      description = "This rule detects intrinsic patterns of Amadey version 5.34"
      date = "2025-06-18"
      score = 80
      reference = "https://0x0d4y.blog/amadey-targeted-analysis/"
      yarahub_reference_md5 = "1db72c5832fb71b29863ccc3125137a0"
      yarahub_uuid = "853111b8-e548-46a9-8f5a-ec8621343e0d"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      malpedia_family = "win.amadey"

   strings:
      $rc4_algorithm = { 8a 96 ?? ?? ?? ?? 0f b6 86 ?? ?? ?? ?? 03 f8 0f b6 ca 03 f9 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 8a 87 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46 88 97 ?? ?? ?? ?? 81 fe 00 01 00 00 7c }
      $s_MZ_PE_validation = { b8 4d 5a ?? ?? 66 39 06 0f 85 a8 01 ?? ?? 8b 7e 3c 03 fe 81 3f 50 45 00 00  }
      $s_loop_through_pe_section = { 8b 4c 24 0c 03 ce 03 4e 3c 6a ?? ff b1 08 01 ?? ?? 8b 81 0c 01 00 00 03 c6 50 8b 81 04 01 ?? ?? 03 44 24 20 50 ff 74 24 30 ff 15 f4 f0 44 00 8b 4c 24 10 0f b7 47 06 41 83 44 24 0c 28 89 4c 24 10 3b c8 }
      $s_str_decryption_algorithm = { 8b cb 0f 43 35 ?? ?? ?? ?? 2b c8 8d 04 0a 33 d2 f7 f3 }

    condition:
      uint16(0) == 0x5a4d 
      and $rc4_algorithm 
      and 2 of ($s*)
}
