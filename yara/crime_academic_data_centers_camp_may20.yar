rule APT_LNX_Academic_Camp_May20_Eraser_1 {
   meta:
      description = "Detects malware used in attack on academic data centers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
      date = "2020-05-16"
      hash1 = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"
      id = "36d17887-9844-5fa4-8a0d-89cc41b2d876"
   strings:
      $sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
               00 00 00 00 89 C7 E8 }
      $sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
               00 00 00 48 89 C7 E8 }
   condition:
      uint16(0) == 0x457f and
      filesize < 60KB and
      all of them
}

rule APT_LNX_Academic_Camp_May20_Loader_1 {
   meta:
      description = "Detects malware used in attack on academic data centers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
      date = "2020-05-16"
      hash1 = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"
      id = "cda65abd-d918-5ee6-8f4a-554d47532d76"
   strings:
      $sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A 
               C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 }
      $sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D }
   condition:
      uint16(0) == 0x457f and
      filesize < 10KB and all of them
}

