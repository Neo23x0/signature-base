
rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_1 {
   meta:
      description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
      id = "492b74c2-3b81-5dff-9244-8528565338c6"
   strings:
      /* OneNote FileDataStoreObject GUID https://blog.didierstevens.com/ */
      $ge1 = "5xbjvWUmEUWkxI1NC3qer"
      $ge2 = "cW471lJhFFpMSNTQt6nq"
      $ge3 = "nFuO9ZSYRRaTEjU0Lep6s"

      /* PE file DOS header */
      $sp1 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG"
      $sp2 = "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl"
      $sp3 = "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ"
      $sp4 = "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVy"
      $sp5 = "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlc"
      $sp6 = "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZX"
      /* @echo off */
      $se1 = "QGVjaG8gb2Zm"
      $se2 = "BlY2hvIG9mZ"
      $se3 = "AZWNobyBvZm"
      /* <HTA:APPLICATION */
      $se4 = "PEhUQTpBUFBMSUNBVElPTi"
      $se5 = "xIVEE6QVBQTElDQVRJT04g"
      $se6 = "8SFRBOkFQUExJQ0FUSU9OI"
      /* LNK file magic header */
      $se7 = "TAAAAAEUAg"
      $se8 = "wAAAABFAIA"
      $se9 = "MAAAAARQCA"
   condition:
      filesize < 5MB
      and 1 of ($ge*)
      and 1 of ($s*)
}

rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2 {
   meta:
      description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
      id = "f8c58c73-2404-5ce6-8e8f-99b0dad84ad0"
   strings:
      /* .one\n\n5FJce */
      $hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }

      $x01 = " attachment; filename=\"Invoice" nocase
      $x02 = " attachment; filename=\"ORDER" nocase
      $x03 = " attachment; filename=\"PURCHASE" nocase
      $x04 = " attachment; filename=\"SHIP" nocase
   condition:
      filesize < 5MB 
      and $hc1 
      and 1 of ($x*)
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_1 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      modified = "2023-02-27"
      score = 65
      id = "b8ea8c7b-052f-5a97-9577-99903462ea84"
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $x1 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4d 5a } // PE
      $x2 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 65 63 68 6f } // @echo off
      $x3 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 45 43 48 4f } // @ECHO OFF
      $x4 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 4F 6E 20 45 } // On Error Resume
      $x5 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 6F 6E 20 65 } // on error resume
      $x6 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4c 00 00 00 } // LNK file
      $x7 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 49 54 53 46 } // CHM file
      $x8 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 68 74 61 3A } // hta:
      $x9 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 48 54 41 3A } // HTA:
      $x10 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 6A 6F 62 20 } // WSF file "<job "
   condition:
      filesize < 10MB and 1 of them
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      score = 65
      id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      $s1 = "<HTA:APPLICATION "
   condition:
      filesize < 5MB
      and $a1 
      and 1 of ($s*)
}
