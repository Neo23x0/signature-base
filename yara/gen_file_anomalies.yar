import "pe"

rule SUSP_TINY_PE {
   meta:
      description = "Detects Tiny PE file"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
      date = "2019-10-23"
      score = 80
      id = "5081c24e-91d1-5705-9459-f675be4f0e3c"
   strings:
      $header = { 4D 5A 00 00 50 45 00 00 }
   condition:
      uint16(0) == 0x5a4d and uint16(4) == 0x4550 and filesize <= 20KB and $header at 0
}

rule SUSP_GIF_Anomalies {
   meta:
      description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://en.wikipedia.org/wiki/GIF"
      date = "2020-07-02"
      id = "2e77c2ff-a8f6-5444-a93d-843312640a28"
   condition:
      uint16(0) == 0x4947 and uint8(2) == 0x46 /* GIF */
      and uint8(11) != 0x00 /* Background Color Index != 0 */
      and uint8(12) != 0x00 /* Pixel Aspect Ratio != 0 */
      and uint8(filesize-1) != 0x3b /* Trailer (trailes are often 0x00 byte padded and cannot server as sole indicator) */
}

rule SUSP_HxD_Icon_Anomaly_May23_1 {
   meta:
      description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
      author = "Florian Roth"
      reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"
      date = "2023-05-29"
      score = 65
      id = "3ac8cc92-6d76-5787-ada0-cfb6eabb4b20"
   strings:
      /* part of the icon bitmap : we're not using resource hashes etc because YARA's string matching is much faster */
      $ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
      $ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

      /* strings to expect in a HxD executable */
      $s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A } /* Developer: Maael Hoerz */
      $s2 = "mh-nexus.de" ascii wide

      /* UPX marker */
      $upx1 = "UPX0" ascii fullword

      /* Keywords that are known to appear in malicious  samples */
      $xs1 = "terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
      $xs2 = "Terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
   condition:
      // HxD indicators
      uint16(0) == 0x5a4d 
      and 1 of ($ac*)
      // Anomalies
      and (
         not 1 of ($s*) // not one of the expected strings
         or filesize > 6930000 // no legitimate sample bigger than 6.6MB
         // all legitimate binaries have a known size and shouldn't be smaller than ...
         or ( pe.is_32bit() and filesize < 1540000 and not $upx1 )
         or ( pe.is_32bit() and filesize < 590000 and $upx1 )
         or ( pe.is_64bit() and filesize < 6670000 and not $upx1 )
         or ( pe.is_64bit() and filesize < 1300000 and $upx1 )
         // keywords expected in malicious samples
         or 1 of ($xs*)
      )
}
