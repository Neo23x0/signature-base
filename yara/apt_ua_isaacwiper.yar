import "pe"

rule MAL_WIPER_IsaacWiper_Mar22_1 {
   meta:
      description = "Detects IsaacWiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
      date = "2022-03-03"
      score = 85
      hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
      hash2 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"
      id = "97d8d8dd-db65-5156-8f97-56c620cf2d56"
   strings:
      $s1 = "C:\\ProgramData\\log.txt" wide fullword
      $s2 = "Cleaner.dll" ascii fullword
      $s3 = "-- system logical drive: " wide fullword
      $s4 = "-- FAILED" wide fullword

      $op1 = { 8b f1 80 3d b0 66 03 10 00 0f 85 96 00 00 00 33 c0 40 b9 a8 66 03 10 87 01 33 db }
      $op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 a2 c8 01 10 2b c1 6a 04 }
      $op3 = { 8d 4d f4 ff 75 08 e8 12 ff ff ff 68 88 39 03 10 8d 45 f4 50 e8 2d 1d 00 00 cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "a4b162717c197e11b76a4d9bc58ea25d" or
         3 of them
      )
}
