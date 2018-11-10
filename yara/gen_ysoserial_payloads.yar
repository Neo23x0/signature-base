/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-04
   Identifier: ysoserial payloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule Ysoserial_Payload_MozillaRhino1 {
   meta:
      description = "Ysoserial Payloads - file MozillaRhino1.bin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
   strings:
      $s3 = "ysoserial.payloads" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 40KB and all of them )
}

rule Ysoserial_Payload_C3P0 {
   meta:
      description = "Ysoserial Payloads - file C3P0.bin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"
   strings:
      $x1 = "exploitppppw" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 3KB and all of them )
}

rule Ysoserial_Payload_Spring1 {
   meta:
      description = "Ysoserial Payloads - file Spring1.bin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      hash1 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
      hash2 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
      hash3 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
      hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
      hash5 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
      hash6 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
      hash7 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
   strings:
      $x1 = "ysoserial/Pwner" ascii
   condition:
      1 of them
}

rule Ysoserial_Payload {
   meta:
      description = "Ysoserial Payloads"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      super_rule = 1
      hash1 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
      hash2 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
      hash3 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
      hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
      hash5 = "747ba6c6d88470e4d7c36107dfdff235f0ed492046c7ec8a8720d169f6d271f4"
      hash6 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
      hash7 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
      hash8 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
      hash9 = "1fea8b54bb92249203d68d5564a01599b42b46fc3a828fe0423616ee2a2f2d99"
      hash10 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
      hash11 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
      hash12 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
      hash13 = "f756c88763d48cb8d99e26b4773eb03814d0bd9bd467cc743ebb1479b2c4073e"
   strings:
      $x1 = "ysoserial/payloads/" ascii

      $s1 = "StubTransletPayload" fullword ascii
      $s2 = "Pwnrpw" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 40KB and $x1 ) or ( all of them )
}

rule Ysoserial_Payload_3 {
   meta:
      description = "Ysoserial Payloads - from files JavassistWeld1.bin, JBossInterceptors.bin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      super_rule = 1
      hash1 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
      hash2 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
   strings:
      $x1 = "ysoserialq" fullword ascii

      $s1 = "targetClassInterceptorMetadatat" fullword ascii
      $s2 = "targetInstancet" fullword ascii
      $s3 = "targetClassL" fullword ascii
      $s4 = "POST_ACTIVATEsr" fullword ascii
      $s5 = "PRE_DESTROYsq" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 10KB and $x1 ) or ( all of them )
}
