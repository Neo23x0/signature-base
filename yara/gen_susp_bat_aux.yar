
rule SUSP_BAT_Aux_Jan20_1 {
   meta:
      description = "Detects BAT file often dropped to cleanup temp dirs during infection"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@quoscient/the-chicken-keeps-laying-new-eggs-uncovering-new-gc-maas-tools-used-by-top-tier-threat-actors-531d80a6b4e9"
      date = "2020-01-29"
      score = 65
      hash1 = "f5d558ec505b635b1e37557350562ad6f79b3da5cf2cf74db6e6e648b7a47127"
      id = "c97f189e-a0c2-532e-b087-8669da72a2ad"
   strings:
      $s1 = "if exist \"C:\\Users\\" ascii
      $s2 = "\\AppData\\Local\\Temp\\" ascii
      $s3 = "del \"C:\\Users\\" ascii
      $s4 = ".bat\"" ascii
      $s5 = ".exe\" goto" ascii
   condition:
      uint8(0) == 0x3a and filesize <= 1KB and all of them
}
