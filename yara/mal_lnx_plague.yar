rule MAL_LNX_PLAGUE_BACKDOOR_Jul25 {
   meta:
      description = "Detects Plague backdoor ELF binaries, related to PAM authentication alteration."
      reference = "Internal Research"
      author = "Pezier Pierre-Henri"
      date = "2025-07-25"
      score = 80
      hash = "14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39"
      hash = "7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e"
   strings:
      $s1 = "decrypt_phrase"
      $s2 = "init_phrases"

      $x1 = "captured_password"
      $x2 = "updateklog"
      $x3 = "init_cred_structs"

      $xop1 = {
         48 8b [4] 00    // mov     rax, cs:_ent_ptr
         8b 00           // mov     eax, [rax]
         3d ca b2 e9 f1  // cmp     eax, 0F1E9B2CAh
         74              // jz      short loc_4586
      }
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 1MB
      and 2 of them
}

