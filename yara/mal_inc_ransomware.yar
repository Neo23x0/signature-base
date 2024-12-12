rule MAL_RANSOM_INC_Aug24 {
   meta:
      author = "X__Junior"
      description = "Detects INC ransomware and it's variants like Lynx"
      reference1 = "https://x.com/rivitna2/status/1817681737251471471"
      reference2 = "https://twitter.com/rivitna2/status/1701739812733014313"
      date = "2024-08-08"
      hash1 = "eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc" // LYNX
      hash2 = "1754c9973bac8260412e5ec34bf5156f5bb157aa797f95ff4fc905439b74357a" // INC
      score = 80
      id = "b776490b-f26a-55d9-bb26-ec3c617f070c"
   strings:
      $s1 = "tarting full encryption in" wide
      $s2 = "oad hidden drives" wide
      $s3 = "ending note to printers" ascii
      $s4 = "uccessfully delete shadow copies from %c:/" wide

      $op1 = { 33 C9 03 C6 83 C0 02 0F 92 C1 F7 D9 0B C8 51 E8 }
      $op2 = { 8B 44 24 [1-4] 6A 00 50 FF 35 ?? ?? ?? ?? 50 FF 15}
      $op3 = { 57 50 8D 45 ?? C7 45 ?? 00 00 00 00 50 6A 00 6A 00 6A 02 6A 00 6A 02 C7 45 ?? 00 00 00 00 FF D6 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 04 8B F8 8D 45 ?? 50 8D 45 ?? 50 FF 75 ?? 57 6A 02 6A 00 6A 02 FF D6 }
      $op4 = { 6A FF 8D 4? ?? 5? 8D 4? ?? 5? 8D 4? ?? 5? 5? FF 15 ?? ?? ?? ?? 85 C0 }
      $op5 = { 56 6A 00 68 01 00 10 00 FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 74 ?? 6A 00 56 FF 15 ?? ?? ?? ?? 68 88 13 00 00 56 FF 15 ?? ?? ?? ?? 56 FF 15}
   condition:
      uint16(0) == 0x5A4D and
      (
         3 of ($s*)
         or 3 of ($op*)
         or (2 of ($s*) and 2 of ($op*) )
      )
}