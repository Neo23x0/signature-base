import "pe"

rule EXT_APT32_goopdate_installer {
  meta:
    reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
    author = "Facebook"
    description = "Detects APT32 installer side-loaded with goopdate.dll"
    sample = "69730f2c2bb9668a17f8dfa1f1523e0e1e997ba98f027ce98f5cbaa869347383"
    id = "08f3cbda-ccb7-517a-b205-5f71de26c735"
  strings:
    $s0 = { 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 33 05 ?? ?? ?? ?? }
    $s1 = "GetProcAddress"
    $s2 = { 8B 4D FC ?? ?? 0F B6 51 0C ?? ?? 8B 4D F0 0F B6 1C 01 33 DA }
    $s3 = "FindNextFileW"
    $s4 = "Process32NextW"

  condition:
    (pe.is_64bit() or pe.is_32bit()) and
    all of them
}

rule EXT_APT32_osx_backdoor_loader {
  meta:
    reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
    author = "Facebook"
    description = "Detects APT32 backdoor loader on OSX"
    sample = "768510fa9eb807bba9c3dcb3c7f87b771e20fa3d81247539e9ea4349205e39eb"
    id = "ac313bd8-bf15-5b72-b651-35015f71dd90"
  strings:
    $a1 = { 00 D2 44 8A 04 0F 44 88 C0 C0 E8 07 08 D0 88 44 0F FF 48 FF C1 48 83 F9 10 44 88 C2 }
    $a2 = { 41 0F 10 04 07 0F 57 84 05 A0 FE FF FF 41 0F 11 04 07 48 83 C0 10 48 83 F8 10 75 }

    // Encrypted data
    $e1 = { CA CF 3E F2 DA 43 E6 D1  D5 6C D4 23 3A AE F1 B2 } // Decoded to drop filepath: '/tmp/panels'
    $e2 = "MlkHVdRbOkra9s+G65MAoLga340t3+zj/u8LPfP3hig=" // Decoded to export API name 'ArchaeologistCodeine'
    $e3 = { 5A 69 98 0E 6C 4B 5C 69  7E 19 34 3B C3 07 CA 13 } // Decoded to 'ifconfig -l'
    $e4 = "1Sib4HfPuRQjpxIpECnxxTPiu3FXOFAHMx/+9MEVv9M+h1ngV7T5WUP3b0zsg0Qd" // Decoded to export API 'PlayerAberadurtheIncomprehensible'

    // Decoded export func names
    $e5 = "_ArchaeologistCodeine"
    $e6 = "_PlayerAberadurtheIncomprehensible"

  condition:
    ((uint32(0) == 0xfeedface or uint32be(0) == 0xfeedface) or (uint32(0) == 0xfeedfacf or uint32be(0) == 0xfeedfacf)) and
   (
      2 of ($e*) or
      all of ($a*)
   )
}
