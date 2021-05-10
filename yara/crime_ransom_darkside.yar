rule MAL_RANSOM_Darkside_May21_1 {
   meta:
      description = "Detects Darkside Ransomware"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
      date = "2021-05-10"
      hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
   strings:
      $op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff }
      $op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f }
      $op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 }
      $op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      3 of them or all of them
}

