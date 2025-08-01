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
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 1MB
      and all of them
}
