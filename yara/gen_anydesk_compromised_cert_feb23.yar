import "pe"

rule PUA_AnyDesk_Compromised_Certificate_Revoked_Jan24 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8) after it was revoked. This is not a threat detection. It detects an outdated version of AnyDesk that was signed with a certificate that has been revoked."
      date = "2024-02-05"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 50
   condition:
      uint16(0) == 0x5a4d 
      and for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"
      )
}

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_1 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; strict version)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 75
   strings:
      $a1 = "AnyDesk Software GmbH" wide
   condition:
      uint16(0) == 0x5a4d 
      and not $a1
      and for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"
      )
}

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_2 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; permissive version)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 65
   strings:
      $sc1 = { 0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8 }
      $s2 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"

      $f1 = "AnyDesk Software GmbH" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20000KB
      and all of ($s*)
      and not 1 of ($f*)
}

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_3 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk after it was revoked (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; version that uses dates for validation)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 75
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8" and
         // valid after Monday, January 29, 2024 0:00:00
         (
            pe.signatures[i].not_before > 1706486400 // certificate validity starts after it was revoked
            or pe.timestamp > 1706486400 // PE was created after it was revoked
         )
      )
}
