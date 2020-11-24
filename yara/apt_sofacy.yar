
import "pe"

rule Sofacy_Campaign_Mal_Feb18_cdnver {
   meta:
      description = "Detects Sofacy malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
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

rule APT_ATP28_Sofacy_Indicators_May19_1 {
   meta:
      description = "Detects APT28 Sofacy indicators in samples"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1129647994603790338"
      date = "2019-05-18"
      score = 60
      hash1 = "80548416ffb3d156d3ad332718ed322ef54b8e7b2cc77a7c5457af57f51d987a"
      hash2 = "b40909ac0b70b7bd82465dfc7761a6b4e0df55b894dd42290e3f72cb4280fa44"
   strings:
      $x1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" ascii
      $x2 = "C:\\Users\\User\\Desktop\\Downloader_Poco" ascii

      $s1 = "w%SystemRoot%\\System32\\npmproxy.dll" fullword wide

      $op0 = { e8 41 37 f6 ff 48 2b e0 e8 99 ff ff ff 48 8b d0 }
      $op1 = { e9 34 3c e3 ff cc cc cc cc 48 8d 8a 20 }
      $op2 = { e8 af bb ef ff b8 ff ff ff ff e9 f4 01 00 00 8b }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and (
         pe.imphash() == "f4e1c3aaec90d5dfa23c04da75ac9501" or
         1 of ($x*) or
         ( $s1 and 2 of ($op*) )
      )
}
