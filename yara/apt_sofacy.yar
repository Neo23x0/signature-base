
import "pe"

rule Sofacy_Campaign_Mal_Feb18_cdnver {
   meta:
      description = "Detects Sofacy malware"
      author = "Florian Roth"
      reference = "https://twitter.com/ClearskySec/status/960924755355369472"
      date = "2018-02-07"
      hash1 = "12e6642cf6413bdf5388bee663080fa299591b2ba023d069286f3be9647547c8"
   strings:
      $x1 = "cdnver.dll" fullword wide
      $x2 = { 25 73 0A 00 00 00 00 00 30 00 00 00 20 00 2D 00
              20 00 00 00 0A 00 00 00 25 00 73 00 00 00 00 00
              69 00 6D 00 61 00 67 00 65 00 2F 00 6A 00 70 00
              65 00 67 }
      $s1 = "S7%s - %lu" fullword ascii
      $s2 = "SNFIRNW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and (
        pe.imphash() == "01f3d0fe6fb9d9df24620e67afc143c7" or
        1 of ($x*) or
        2 of them
      )
}

rule Sofacy_Trojan_Loader_Feb18_1 {
   meta:
      description = "Sofacy Activity Feb 2018"
      author = "Florian Roth"
      reference = "https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100"
      date = "2018-03-01"
      hash1 = "335565711db93cd02d948f472c51598be4d62d60f70f25a20449c07eae36c8c5"
   strings:
      $x1 = "%appdata%\\nad.dll" fullword wide
      $s3 = "%appdata%\\nad.bat" fullword wide

      $s1 = "apds.dll" fullword ascii
      $s2 = "nad.dll\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
        pe.imphash() == "a2d1be6502b4b3c28959a4fb0196ea45" or
        pe.exports("VidBitRpl") or
        1 of ($x*) or
        2 of them
      )
}
