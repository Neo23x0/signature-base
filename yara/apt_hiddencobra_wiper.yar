/*
   Author: NCCIC Partner
   Date: 2018-03-28
   Identifier: HiddenCobra
   Reference: https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf
*/

rule HiddenCobra_r4_wiper_1 {
   meta:
      author = "NCCIC Partner"
      date = "2017-12-12"
      description = "Detects HiddenCobra Wiper"
      reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
   strings:
      $mbr_code = { 33 C0 8E D0 BC 00 7C FB 50 07 50 1F FC BE 5D 7C 33 C9 41 81 F9 00 ?? 74 24 B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 83 55 06 00 EB D5 BE 4D 7C B4 43 B0 00 CD 13 33 C9 BE 5D 7C EB C5 }
      $controlServiceFoundlnBoth = { 83 EC 1C 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 44 8B 44 24 24 53 56 6A 24 50 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 1C 8D 4C 24 0C 51 6A 01 56 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 56 FF D3 57 FF D3 5E 5B 33 C0 5F 83 C4 1C C3 33 C0 5F 83 C4 1C C3 }
   condition:
      uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and any of them
}

rule HiddenCobra_r4_wiper_2 {
   meta:
      author = "NCCIC Partner"
      date = "2017-12-12"
      description = "Detects HiddenCobra Wiper"
      reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
   strings:
      // BIOS Extended Write
      $PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
      $ExtendedWrite = { B4 43 B0 00 CD 13 }
   condition:
      uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them
}
