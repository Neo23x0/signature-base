
rule STUXSHOP_config {
   meta:
      desc = "Stuxshop standalone sample configuration"
      author = "JAG-S (turla@chronicle.security)"
      hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
      reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
   strings:
      $cnc1 = "http://211.24.237.226/index.php?data=" ascii wide
      $cnc2 = "http://todaysfutbol.com/index.php?data=" ascii wide
      $cnc3 = "http://78.111.169.146/index.php?data=" ascii wide
      $cnc4 = "http://mypremierfutbol.com/index.php?data=" ascii wide
      $regkey1 = "Software\\Microsoft\\Windows\\CurrentVersion\\MS-DOS Emulation" ascii wide
      $regkey2 = "NTVDMParams" ascii wide

      $flowerOverlap1 = { 85 C0 75 3B 57 FF 75 1C FF 75 18 FF 75 14 50 FF 75 10 FF 75 FC FF 15 }
      $flowerOverlap2 = { 85 C0 75 4C 8B 45 1C 89 45 0C 8D 45 0C 50 8D 45 08 FF 75 18 50 6A 00 FF 75 10 FF 75 20 FF 15 }
      $flowerOverlap3 = { 55 8B EC 53 56 8B 75 20 85 F6 74 03 83 26 00 8D 45 20 50 68 19 00 02 00 6A 00 FF 75 0C FF 75 08 }
      $flowerOverlap4 = { 55 8B EC 51 8D 4D FC 33 C0 51 50 6A 26 50 89 45 FC FF 15 }
      $flowerOverlap5 = { 85 DB 74 04 8B C3 EB 1A 8B 45 08 3B 45 14 74 07 B8 5D 06 00 00 EB 0B 85 F6 74 05 8B 45 0C 89 06 }
      $flowerOverlap6 = { 85 FF 74 12 83 7D F8 01 75 0C FF 75 0C FF 75 08 FF 15 }

   condition:
      all of ($flowerOverlap*)
      or
      2 of ($cnc*)
      or
      all of ($regkey*)
}

rule STUXSHOP_OSCheck {
   meta:
      author = "Silas Cutler (havex@Chronicle.Security)"
      desc = "Identifies the OS Check function in STUXSHOP and CheshireCat"
      hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
   strings:
      $ = {10 F7 D8 1B C0 83 C0 ?? E9 ?? 01 00 00 39 85 7C FF FF FF 0F 85 ?? 01 00
      00 83 BD 70 FF FF FF 04 8B 8D 74 FF FF FF 75 0B 85 C9 0F 85 ?? 01 00 00 6A 05
      5E }
      $ = {01 00 00 3B FA 0F 84 ?? 01 00 00 80 7D 80 00 B1 62 74 1D 6A 0D 8D 45 80
      68 ?? ?? ?? 10 50 FF 15 ?? ?? ?? 10 83 C4 0C B1 6F 85 C0 75 03 8A 4D 8D 8B C6
      }
   condition:
      any of them
}
