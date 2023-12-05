
rule APT_APT28_Cannon_Trojan_Nov18_1 {
   meta:
      description = "Detects Cannon Trojan used by Sofacy"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/11/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/"
      date = "2018-11-20"
      hash1 = "61a1f3b4fb4dbd2877c91e81db4b1af8395547eab199bf920e9dd11a1127221e"
      id = "a60f3e75-8bfe-592e-90d1-321bd86173ac"
   strings:
      $xc1 = { 46 6F 72 6D 31 00 63 61 6E 6E 6F 6E 00 4D 44 61
               74 00 41 55 54 48 }
      $xc2 = { 13 4F 00 53 00 3A 00 20 00 20 00 7B 00 30 00 7D
               00 0A 00 00 17 53 00 44 00 69 00 72 00 3A 00 20
               00 20 00 7B 00 30 00 7D 00 0A 00 00 1B 44 00 6F
               00 6D 00 61 00 69 00 6E 00 3A 00 20 00 20 00 7B
               00 30 00 7D 00 0A 00 00 15 48 00 6F 00 73 00 74
               00 3A 00 20 00 7B 00 30 00 7D 00 0A 00 00 21 43
               00 75 00 72 00 72 00 65 00 6E 00 74 00 55 00 73
               00 72 00 3A 00 20 00 7B 00 30 00 7D 00 0A 00 00
               17 54 00 69 00 6D 00 65 00 5A 00 3A 00 20 00 7B
               00 30 00 7D }
      $x2 = "\\Desktop\\cannon\\obj\\" ascii
      $x3 = "C:\\Users\\Public\\Music\\s.txt" fullword wide

      $s1 = "C:\\Documents and Settings\\All Users\\Documents" fullword wide
      $s2 = "notEncoded - Value here is never used" fullword wide
      $s3 = "Windows NT\\CurrentVersion\\Winlogon\"" fullword wide
      $s4 = "AnswerMessageTraverser`1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of ($x*) or 3 of them
}
