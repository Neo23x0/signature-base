import "pe"

rule MAL_RANSOM_Venus_Nov22_1 {
   meta:
      description = "Detects Venus Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
      date = "2022-11-16"
      score = 85
      hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
      hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
      hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
      hash4 = "969bfe42819e30e35ca601df443471d677e04c988928b63fccb25bf0531ea2cc"
      hash5 = "db6fcd33dcb3f25890c28e47c440845b17ce2042c34ade6d6508afd461bfa21c"
      hash6 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
      hash7 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
      id = "0f7e0ca4-c5e2-5557-92de-2e0d73035f12"
   strings:
      $x1 = "<html><head><title>Venus</title><style type = \"text" ascii fullword
      $x2 = "xXBLTZKmAu9pjcfxrIK4gkDp/J9XXATjuysFRXG4rH4=" ascii fullword
      $x3 = "%s%x%x%x%x.goodgame" wide fullword

      $s1 = "/c ping localhost -n 3 > nul & del %s" ascii fullword
      $s2 = "C:\\Windows\\%s.png" wide

      $op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 }
      $op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e }
      $op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "bb2600e94092da119ee6acbbd047be43" or
         1 of ($x*) or
         2 of them
      ) 
      or 4 of them
}

