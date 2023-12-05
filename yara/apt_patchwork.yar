
rule APT_ArtraDownloader2_Aug19_1 {
   meta:
      description = "Detects ArtraDownloader malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/multiple-artradownloader-variants-used-by-bitter-to-target-pakistan/"
      date = "2019-08-27"
      hash1 = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"
      id = "0e688e92-2366-5f36-a32d-083982181eb7"
   strings:
      $xc1 = { 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 30 00
               0D 0A 00 00 48 6F 73 74 3A 20 25 73 00 00 00 00
               3F 61 3D 00 26 62 3D 00 26 63 3D 00 26 64 3D 00
               26 65 3D 00 25 32 30 }
      $xc2 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D
               0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 25 73 20
               25 64 0D 0A 0D 0A 25 73 00 00 00 00 71 72 79 3D }
      $xc3 = { 49 44 3D 25 73 00 00 00 3A 00 00 00 25 73 20 25
               73 20 25 73 0D 0A 25 73 20 25 73 0D 0A 25 73 25
               73 0D 0A 25 73 25 73 0D 0A 43 6F 6E 74 65 6E 74
               2D 6C 65 6E 67 74 68 25 73 20 25 64 }
      $xc4 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D
               0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 43 6F 6E
               74 65 6E 74 2D 6C 65 6E 67 74 68 3A 20 25 64 0D
               0A 0D 0A 25 73 }
      $x1 = "Tpguxbsf]Njdsptpgu" ascii
      $x2 = ".gpsn.vsmfodpefe" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and 1 of them
}
