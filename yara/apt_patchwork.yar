
rule APT_ArtraDownloader2_Aug19_1 {
   meta:
      description = "Detects ArtraDownloader malware"
      author = "Florian Roth"
      reference = "https://unit42.paloaltonetworks.com/multiple-artradownloader-variants-used-by-bitter-to-target-pakistan/"
      date = "2019-08-27"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"
   strings:
      $xc1 = { 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 30 00
               0D 0A 00 00 48 6F 73 74 3A 20 25 73 00 00 00 00
               3F 61 3D 00 26 62 3D 00 26 63 3D 00 26 64 3D 00
               26 65 3D 00 25 32 30 }

      $sc1 = { 47 45 54 20 2F 00 00 00 20 48 54 54 50 2F 31 2E
               31 0D 0A 00 48 6F 73 74 3A 20 00 00 25 73 25 73
               25 73 25 73 25 73 25 73 25 73 25 73 }
      $sc2 = { 59 65 73 20 66 69 6C 65 00 00 00 00 2E 65 78 65
               00 00 00 00 6F 70 65 6E 00 00 00 00 5C 2F 00 00
               0A 00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (1 of ($x*) or 2 of them)
}
