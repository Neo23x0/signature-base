
rule SUSP_VEST_Encryption_Core_Accumulator_Jan21 {
   meta:
      description = "Detects VEST encryption core accumulator in PE file as used by Lazarus malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ochsenmeier/status/1354737155495649280"
      date = "2021-01-28"
      score = 70
      hash1 = "7cd3ca8bdfb44e98a4b9d0c6ad77546e03d169bda9bdf3d1bcf339f68137af23"
      id = "8343652b-8865-5213-b735-d6d4084e4a84"
   strings:
      $sc1 = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89
               26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2
               B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97
               25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7
               96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7
               0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72
               85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51
               AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E
               96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85
               9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 }
   condition:
      uint16(0) == 0x5a4d and
      1 of them
}
