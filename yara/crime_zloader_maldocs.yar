
rule MAL_DOC_ZLoader_Oct20_1 {
   meta:
      description = "Detects weaponized ZLoader documents"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
      date = "2020-10-10"
      hash1 = "668ca7ede54664360b0a44d5e19e76beb92c19659a8dec0e7085d05528df42b5"
      hash2 = "a2ffabbb1b5a124f462a51fee41221081345ec084d768ffe1b1ef72d555eb0a0"
      hash3 = "d268af19db475893a3d19f76be30bb063ab2ca188d1b5a70e51d260105b201da"
      id = "34145746-9733-5dd9-9dcf-99e3a3ceee4f"
   strings:
      $sc1 = { 78 4E FC 04 AB 6B 17 E2 33 E3 49 62 50 69 BB 60
               31 00 1E 00 02 4B BA E2 D8 E3 92 22 1E 69 96 20
               98 }
      $sc2 = { 6B 9E E2 36 E3 69 62 72 69 3A 60 55 6E }
      $sc3 = { 3E 69 76 60 59 6E 34 FB 87 6B 75 }
   condition:
      uint16(0) == 0xcfd0 and
      filesize < 40KB and filesize > 30KB and
      all of them
}
