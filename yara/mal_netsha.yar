
rule MAL_Neshta_Mar20_1 {
   meta:
      description = "Detects Neshta malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-03-24"
      hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
   strings:
      $x1 = "the best. Fuck off all the rest."
      $x2 = "Neshta 1.0 Made in Belarus. " ascii

      $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
      $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
      $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      1 of ($x*) or 3 of them
}

rule MAL_Neshta_Feb20_1 {
   meta:
      description = "Detects Neshta malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-02-24"
      hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
      hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
      hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"
   strings:
      $op1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
      $op2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
   condition:
      uint16(0) == 0x5a4d and filesize >= 3000KB and filesize <= 8000KB and all of them
}
