/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-13
   Identifier: Hidden Cobra
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-164A
*/

/* Rule Set ----------------------------------------------------------------- */

rule HiddenCobra_Rule_1 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94
            A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77
            48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39
            73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2
            AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED
            39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68
            3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13
            B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}
   condition:
      all of them
}

/* Prone to False Positives ----------------------------------------
rule HiddenCobra_Rule_2 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $STR1 = "Wating" wide ascii fullword
      $STR2 = "Reamin" wide ascii fullword
      $STR3 = "laptos" wide ascii fullword
   condition:
      ( uint16(0) == 0x5A4D or
        uint16(0) == 0xCFD0 or
        uint16(0) == 0xC3D4 or
        uint32(0) == 0x46445025 or
        uint32(1) == 0x6674725C
      ) and all of them
}
*/

rule HiddenCobra_Rule_3 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7
         44 24 28 B4 6F 41 00 C7 44 24 2C B0 6F 41 00 C7 44 24 30 AC 6F 41
         00 C7 44 24 34 A8 6F 41 00 C7 44 24 38 A4 6F 41 00 C7 44 24 3C A0
         6F 41 00 C7 44 24 40 9C 6F 41 00 C7 44 24 44 94 6F 41 00 C7 44 24
         48 8C 6F 41 00 C7 44 24 4C 88 6F 41 00 C7 44 24 50 80 6F 41 00 89
         44 24 54 C7 44 24 10 7C 6F 41 00 C7 44 24 14 78 6F 41 00 C7 44 24
         18 74 6F 41 00 C7 44 24 1C 70 6F 41 00 C7 44 24 20 6C 6F 41 00 89
         44 24 24 FF D7 99 B9 0B 00 00 00 F7 F9 8B 74 94 28 BA 9C 6F 41 00
         66 8B 06 66 3B 02 74 34 8B FE 83 C9 FF 33 C0 8B 54 24 60 F2 AE 8B
         6C 24 5C A1 ?? ?? ?? ?? F7 D1 49 89 45 00 8B FE 33 C0 8D 5C 11 05
         83 C9 FF 03 DD F2 AE F7 D1 49 8B FE 8B D1 EB 78 FF D7 99 B9 05 00
         00 00 8B 6C 24 5C F7 F9 83 C9 FF 33 C0 8B 74 94 10 8B 54 24 60 8B
         FE F2 AE F7 D1 49 BF 60 6F 41 00 8B D9 83 C9 FF F2 AE F7 D1 8B C2
         49 03 C3 8B FE 8D 5C 01 05 8B 0D ?? ?? ?? ?? 89 4D 00 83 C9 FF 33
         C0 03 DD F2 AE F7 D1 49 8D 7C 2A 05 8B D1 C1 E9 02 F3 A5 8B CA 83
         E1 03 F3 A4 BF 60 6F 41 00 83 C9 FF F2 AE F7 D1 49 BE 60 6F 41 00
         8B D1 8B FE 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FB 2B F9 8B CA 8B C1
         C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7C 24 60 8D 75 04 57 56 E8
         ?? ?? ?? ?? 83 C4 08 C6 04 3E 2E 8B C5 C6 03 00 5F 5E 5D 5B 83 C4
         48 C3 }
   condition:
      $randomUrlBuilder
}


import "pe"

rule APT_HiddenCobra_GhostSecret_1 {
   meta:
      description = "Detects Hidden Cobra Sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11"
      hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
   strings:
      $s1 = "%s\\%s.dll" fullword wide
      $s2 = "PROXY_SVC_DLL.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule APT_HiddenCobra_GhostSecret_2 {
   meta:
      description = "Detects Hidden Cobra Sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11"
      hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"
   strings:
      $s1 = "ping 127.0.0.1 -n 3" fullword wide
      $s2 = "Process32" fullword ascii
      $s11 = "%2d%2d%2d%2d%2d%2d" fullword ascii
      $s12 = "del /a \"" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}


import "pe"

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
   strings:
      $s1 = "www.naver.com" fullword ascii
      $s2 = "PolarSSL Test CA0" fullword ascii
   condition:
      filesize < 1000KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_2 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "70034b33f59c6698403293cdc28676c7daa8c49031089efa6eefce41e22dccb3"
   strings:
      $s1 = "%SystemRoot%\\System32\\svchost.exe -k mdnetuse" fullword ascii
      $s2 = "%s\\hid.dll" fullword ascii
      $s3 = "%Systemroot%\\System32\\" fullword ascii
      $s4 = "SYSTEM\\CurrentControlSet\\services\\%s\\Parameters" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_3 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "2151c1977b4555a1761c12f151969f8e853e26c396fa1a7b74ccbaf3a48f4525"
      hash2 = "05feed9762bc46b47a7dc5c469add9f163c16df4ddaafe81983a628da5714461"
      hash3 = "ddea408e178f0412ae78ff5d5adf2439251f68cad4fd853ee466a3c74649642d"
   strings:
      $s1 = "Oleaut32.dll" fullword ascii
      $s2 = "Process32NextA" fullword ascii
      $s3 = "Process32FirstA" fullword ascii
      $s4 = "%sRSA key size  : %d bits" fullword ascii
      $s5 = "emailAddress=" fullword ascii
      $s6 = "%scert. version : %d" fullword ascii
      $s7 = "www.naver.com" fullword ascii

      $x1 = "ztretrtireotreotieroptkierert" fullword ascii
      $x2 = "reykfgkodfgkfdskgdfogpdokgsdfpg" fullword ascii
      $x3 = "fjiejffndxklfsdkfjsaadiepwn" fullword ascii
      $x4 = "fgwljusjpdjah" fullword ascii
      $x5 = "udbcgiut.dat" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and (
            1 of ($x*) or
            6 of ($s*)
      )
}
