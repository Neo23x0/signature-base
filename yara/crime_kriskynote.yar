
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-03
   Identifier: Kriskynote 03 March
*/

/* Rule Set ----------------------------------------------------------------- */

rule Kriskynote_Mar17_1 {
   meta:
      description = "Detects Kriskynote Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03"
      hash1 = "a19c4b615aa54207604b181873e614d84126b639fee2cce3ca9d5bd863f6f577"
      hash2 = "62b41db0bf63fa45a2c2b0f5df8c2209a5d96bf2bddf82749595c66d30b7ec61"
   strings:
      $s1 = "gzwrite64" fullword ascii

      $opa1 = { e8 6b fd ff ff 83 f8 ff 74 65 83 7b 28 00 74 42 } /* Opcode */

      $opb1 = { 8a 04 08 8b 8e a4 16 00 00 88 44 24 0c 66 c7 04 } /* Opcode */
      $opb2 = { 89 4e 6c 89 46 74 e9 ad fc ff ff 8b 46 68 85 c0 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and $s1 and ($opa1 or all of ($opb*))
}

rule Kriskynote_Mar17_2 {
   meta:
      description = "Detects Kriskynote Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03"
      hash1 = "cb9a2f77868b28d98e4f9c1b27b7242fec2f2abbc91bfc21fe0573e472c5dfcb"
   strings:
      $s1 = "fgjfcn8456fgjhfg89653wetwts" fullword ascii
      $op0 = { 33 c0 80 34 30 03 40 3d e6 21 00 00 72 f4 b8 e6 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule Kriskynote_Mar17_3 {
   meta:
      description = "Detects Kriskynote Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03"
      hash1 = "fc838e07834994f25b3b271611e1014b3593278f0703a4a985fb4234936df492"
   strings:
      $s1 = "rundll32 %s Check" fullword ascii
      $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" fullword ascii
      $s3 = "name=\"IsUserAdmin\"" fullword ascii
      $s4 = "zok]\\\\\\ZZYYY666564444" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them )
}
