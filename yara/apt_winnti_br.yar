import "pe"

rule MAL_Winnti_BR_Report_TwinPeaks {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "2e4e2b88-fdb4-5adc-8192-a304d71ca851"
   strings:
      $cooper = "Cooper"
      $pattern = { e9 ea eb ec ed ee ef f0}
   condition:
      uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}

rule MAL_BR_Report_TheDao {
   meta:
      description = "Detects indicator in malicious UPX packed samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "5cc932d7-2ec6-5570-af4a-3f64b39e6db5"
  strings:
    $b = { DA A0 }
  condition:
    uint16(0) == 0x5a4d and $b at pe.overlay.offset and pe.overlay.size > 100
}

rule MAL_Winnti_BR_Report_MockingJay {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "9aff9d65-3827-59de-9dc3-38f227155d3d"
  strings:
    $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
    $iter = { E9 EA EB EC ED EE EF F0 }
    $jpeg = { FF D8 FF E0 00 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5a4d and
      $jpeg and
      ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
      for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}
