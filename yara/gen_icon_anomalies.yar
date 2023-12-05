import "pe"

rule SUSP_AdobePDF_SFX_Bitmap_Combo_Executable {
   meta:
      description = "Detects a suspicious executable that contains both a SFX icon and an Adobe PDF icon"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mp.weixin.qq.com/s/3Pa3hiuZyQBspDzH0kGSHw"
      date = "2020-11-02"
      score = 60
      hash1 = "13655f536fac31e6c2eaa9e6e113ada2a0b5e2b50a93b6bbfc0aaadd670cde9b"
      id = "d2d078c9-fbe5-51f4-8f7e-5d943c5a8197"
   strings:
      /* Adobe PDF Icon Bitmap */
      $sc1 = { FF 00 CC FF FF 00 99 FF FF 00 66 FF FF 00 33 FF
               FF 80 00 FF FF 80 FF CC FF 80 CC CC FF C0 99 CC
               FF 80 66 CC FF 00 33 CC FF 00 00 CC FF 00 FF 99
               FF FF CC 99 FF FF 99 99 FF FF 66 99 FF FF 33 99
               FF 08 00 99 FF 88 FF 66 FF 88 CC 66 FF 88 99 66
               FF 88 66 66 FF 88 33 66 FF 05 00 66 FF 55 FF 33
               FF 55 CC 33 FF 55 99 33 FF 55 66 33 FF 58 33 33
               FF 01 00 33 FF 99 FF 00 FF 99 CC 00 FF 99 99 00
               FF 99 66 00 FF 58 33 00 FF 01 00 00 FF 99 FF FF
               CC 99 CC FF CC 99 99 FF CC 99 66 FF CC 58 33 FF
               CC 01 00 FF CC FF FF CC CC FF CC CC CC FF 99 CC
               CC FF 66 CC CC 58 33 CC CC 01 00 CC CC FF FF 99 }
      /* SFX Icon Bitmap */
      $sc2 = { 28 66 27 00 60 00 00 00 80 00 00 00 80 80 80 00
               C0 C0 C0 00 FF FF FF 00 FF FF FF 00 FF FF FF 00
               FF FF FF 00 FF FF FF 00 FF FF FF 00 FF FF FF 00
               FF FF FF 00 FF FF FF 00 5D 33 00 00 5D 33 00 00
               5D 33 00 00 5D 33 00 00 5D 33 00 00 5D 33 00 00
               5D 33 00 00 5D 33 00 00 5D 33 00 00 5D 33 00 00 }
   condition:
      uint16(0) == 0x5a4d and
      all of them
      and pe.number_of_signatures < 1
}

rule SUSP_AdobePDF_Bitmap_Executable {
   meta:
      description = "Detects a suspicious executable that contains a Adobe PDF icon and no shows no sign of actual Adobe software"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mp.weixin.qq.com/s/3Pa3hiuZyQBspDzH0kGSHw"
      date = "2020-11-02"
      score = 60
      hash1 = "13655f536fac31e6c2eaa9e6e113ada2a0b5e2b50a93b6bbfc0aaadd670cde9b"
      id = "86ebadd4-64a8-5290-b45e-ac125a10ea66"
   strings:
      /* Adobe PDF Icon Bitmap */
      $sc1 = { FF 00 CC FF FF 00 99 FF FF 00 66 FF FF 00 33 FF
               FF 80 00 FF FF 80 FF CC FF 80 CC CC FF C0 99 CC
               FF 80 66 CC FF 00 33 CC FF 00 00 CC FF 00 FF 99
               FF FF CC 99 FF FF 99 99 FF FF 66 99 FF FF 33 99
               FF 08 00 99 FF 88 FF 66 FF 88 CC 66 FF 88 99 66
               FF 88 66 66 FF 88 33 66 FF 05 00 66 FF 55 FF 33
               FF 55 CC 33 FF 55 99 33 FF 55 66 33 FF 58 33 33
               FF 01 00 33 FF 99 FF 00 FF 99 CC 00 FF 99 99 00
               FF 99 66 00 FF 58 33 00 FF 01 00 00 FF 99 FF FF
               CC 99 CC FF CC 99 99 FF CC 99 66 FF CC 58 33 FF
               CC 01 00 FF CC FF FF CC CC FF CC CC CC FF 99 CC
               CC FF 66 CC CC 58 33 CC CC 01 00 CC CC FF FF 99 }
      /* Exclude actual Adobe software */
      $fp1 = "Adobe" ascii wide fullword
   condition:
      uint16(0) == 0x5a4d and
      $sc1 and not 1 of ($fp*)
      and pe.number_of_signatures < 1
}
