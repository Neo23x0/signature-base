
rule MAL_RANSOM_DarkBit_Feb23_1 {
   meta:
      description = "Detects indicators found in DarkBit ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
      date = "2023-02-13"
      score = 75
      id = "d209a0c2-f649-5fb1-9ecd-f1c35caa796f"
   strings:
      $s1 = ".onion" ascii
      $s2 = "GetMOTWHostUrl"

      $x1 = "hus31m7c7ad.onion"
      $x2 = "iw6v2p3cruy"
      $xn1 = "You will receive decrypting key after the payment."
   condition:
      uint16(0) == 0x5a4d and
      filesize < 10MB and (
         1 of ($x*) or 2 of them
      ) or 4 of them
      or ( filesize < 10MB and $xn1 ) // Ransom note
}

rule MAL_RANSOM_DarkBit_Feb23_2 {
   meta:
      description = "Detects Go based DarkBit ransomware (garbled code; could trigger on other obfuscated samples, too)"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff?environmentId=160"
      date = "2023-02-13"
      score = 75
      hash1 = "9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff"
      id = "f530815c-68e7-55f1-8e36-bc74a1059584"
   strings:
      $s1 = "runtime.initLongPathSupport" ascii fullword
      $s2 = "reflect." ascii
      $s3 = "    \"processes\": []," ascii fullword
      $s4 = "^!* %!(!" ascii fullword

      $op1 = { 4d 8b b6 00 00 00 00 48 8b 94 24 40 05 00 00 31 c0 87 82 30 03 00 00 b8 01 00 00 00 f0 0f c1 82 00 03 00 00 48 8b 44 24 48 48 8b 0d ba 1f 32 00 }
      $op2 = { 49 8d 49 01 0f 1f 00 48 39 d9 7c e2 b9 0b 00 00 00 49 89 d8 e9 28 fc ff ff e8 89 6c d7 ff }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 20000KB and all of them
}
