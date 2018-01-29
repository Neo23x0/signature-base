/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-29
   Identifier: TopHat
   Reference: https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule TopHat_Malware_Jan18_1 {
   meta:
      description = "Detects malware from TopHat campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
      date = "2018-01-29"
      hash1 = "5c0b253966befd57f4d22548f01116ffa367d027f162514c1b043a747bead596"
      hash2 = "1f9bca1d5ce5d14d478d32f105b3ab5d15e1c520bde5dfca22324262e84d4eaf"
   strings:
      $s1 = "WINMGMTS:\\\\.\\ROOT\\CIMV2" fullword ascii
      $s2 = "UENCRYPTION" fullword ascii
      $s3 = "TEXPORTAPIS" fullword ascii
      $s4 = "tcustommemorystream" fullword ascii
      $s5 = "tmemorystream" fullword ascii
      $s6 = "ExtrasNoteCONSOLEemb" fullword ascii
      $s7 = "DIALOG INCLUDE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
        pe.imphash() == "c221006b240b1c993217bd61e5ee31b6" or
        6 of them
      )
}

rule TopHat_Malware_Jan18_2 {
   meta:
      description = "Auto-generated rule - file e.exe"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
      date = "2018-01-29"
      hash1 = "9580d15a06cd59c01c59bca81fa0ca8229f410b264a38538453f7d97bfb315e7"
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
      $s2 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii
      $s3 = "LError loading dock zone from the stream. Expecting version %d, but found %d." fullword wide
      $s4 = "WINMGMTS:\\\\.\\ROOT\\CIMV2" fullword ascii
      $s5 = "UENCRYPTION" fullword ascii
      $s6 = "TEXPORTAPIS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
        pe.imphash() == "f98cebcae832abc3c46e6e296aecfc03" and
        5 of them
      )
}

rule TopHat_BAT {
   meta:
      description = "Auto-generated rule - file cgen.bat"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
      date = "2018-01-29"
      hash1 = "f998271c4140caad13f0674a192093092e2a9f7794a7fbbdaa73ae8f2496c387"
      hash2 = "0fbc6fd653b971c8677aa17ecd2749200a4a563f9dd5409cfb26d320618db3e2"
   strings:
      $s1 = "= New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"" ascii
      $s2 = "goto Start" fullword ascii
      $s3 = ":Start" fullword ascii
   condition:
      filesize < 5KB and all of them
}
