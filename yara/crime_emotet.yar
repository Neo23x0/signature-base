
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
