
rule Malware_Floxif_mpsvc_dll {
   meta:
      description = "Malware - Floxif"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-07"
      hash1 = "1e654ee1c4736f4ccb8b5b7aa604782cfb584068df4d9e006de8009e60ab5a14"
   strings:
      $op1 = { 04 80 7a 03 01 75 04 8d 42 04 c3 8d 42 04 53 8b }
      $op2 = { 88 19 74 03 41 eb ea c6 42 03 01 5b c3 8b 4c 24 }
      $op3 = { ff 03 8d 00 f9 ff ff 88 01 eb a1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}
