/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-08-24
   Identifier: Lazarus - Operation Applejeus
   Reference: https://securelist.com/operation-applejeus/87553/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_Lazarus_Aug18_Downloader_1 {
   meta:
      description = "Detects Lazarus Group Malware Downloadery"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/operation-applejeus/87553/"
      date = "2018-08-24"
      hash1 = "d555dcb6da4a6b87e256ef75c0150780b8a343c4a1e09935b0647f01d974d94d"
      hash2 = "bdff852398f174e9eef1db1c2d3fefdda25fe0ea90a40a2e06e51b5c0ebd69eb"
      hash3 = "e2199fc4e4b31f7e4c61f6d9038577633ed6ad787718ed7c39b36f316f38befd"
   strings:
      $x1 = "H:\\DEV\\TManager\\" ascii
      $x2 = "\\Release\\dloader.pdb" ascii
      $x3 = "Z:\\jeus\\"
      $x4 = "\\Debug\\dloader.pdb" ascii
      $x5 = "Moz&Wie;#t/6T!2yW29ab@ad%Df324V$Yd" fullword ascii

      $s1 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" fullword ascii
      $s2 = "Error protecting memory page" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         ( 1 of ($x*) or 2 of them )
      )
}

rule APT_Lazarus_Aug18_1 {
   meta:
      description = "Detects Lazarus Group Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/operation-applejeus/87553/"
      date = "2018-08-24"
      hash1 = "ef400d73c6920ac811af401259e376458b498eb0084631386136747dfc3dcfa8"
      hash2 = "1b8d3e69fc214cb7a08bef3c00124717f4b4d7fd6be65f2829e9fd337fc7c03c"
   strings:
      $s1 = "mws2_32.dll" fullword wide
      $s2 = "%s.bat" fullword wide
      $s3 = "%s%s%s \"%s > %s 2>&1\"" fullword wide
      $s4 = "Microsoft Corporation. All rights reserved." fullword wide
      $s5 = "ping 127.0.0.1 -n 3" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "3af996e4f960108533e69b9033503f40" or
         4 of them
      )
}

rule APT_Lazarus_Aug18_2 {
   meta:
      description = "Detects Lazarus Group Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/operation-applejeus/87553/"
      date = "2018-08-24"
      hash1 = "8ae766795cda6336fd5cad9e89199ea2a1939a35e03eb0e54c503b1029d870c4"
      hash2 = "d3ef262bae0beb5d35841d131b3f89a9b71a941a86dab1913bda72b935744d2e"
   strings:
      $s1 = "vAdvapi32.dll" fullword wide
      $s2 = "lws2_32.dll" fullword wide
      $s3 = "%s %s > \"%s\" 2>&1" fullword wide
      $s4 = "Not Service" fullword wide
      $s5 = "ping 127.0.0.1 -n 3" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         4 of them
      )
}

rule APT_FallChill_RC4_Keys {
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "Detects FallChill RC4 keys"
      reference = "https://securelist.com/operation-applejeus/87553/"
      date = "2018-08-21"
   strings:
      /* MOV POS 4BYTE-OF-KEY */
      $cod0 = { c7 ?? ?? da e1 61 ff
                c7 ?? ?? 0c 27 95 87
                c7 ?? ?? 17 57 a4 d6
                c7 ?? ?? ea e3 82 2b }
   condition:
      uint16(0) == 0x5a4d and 1 of them
}
