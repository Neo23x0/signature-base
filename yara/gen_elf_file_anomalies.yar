
rule SUSP_ELF_LNX_UPX_Compressed_File {
   meta:
      description = "Detects a suspicious ELF binary with UPX compression"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-12-12"
      score = 40
      hash1 = "038ff8b2fef16f8ee9d70e6c219c5f380afe1a21761791e8cbda21fa4d09fdb4"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s3 = "$Id: UPX" fullword ascii
   condition:
      uint32be(0) == 0x7f454c46 and filesize < 2000KB and filesize > 30KB and all of them
}
