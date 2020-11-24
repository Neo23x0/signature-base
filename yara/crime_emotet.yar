
rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}

import "pe"

rule MAL_Emotet_Jan20_1 {
   meta:
      description = "Detects Emotet malware"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/5e81638e-df2e-4a5b-9e45-b07c38d53929/"
      date = "2020-01-29"
      hash1 = "e7c22ccdb1103ee6bd15c528270f56913bb2f47345b360802b74084563f1b73d"
   strings:
      $op0 = { 74 60 8d 34 18 eb 54 03 c3 50 ff 15 18 08 41 00 }
      $op1 = { 03 fe 66 39 07 0f 85 2a ff ff ff 8b 4d f0 6a 20 }
      $op2 = { 8b 7d fc 0f 85 49 ff ff ff 85 db 0f 84 d1 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 200KB and (
         pe.imphash() == "009889c73bd2e55113bf6dfa5f395e0d" or
         1 of them
      )
}
