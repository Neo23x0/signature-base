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
      $cod1 = { c7 ?? ?? 6c b3 4a f5
                c7 ?? ?? 51 b3 fb 63
                c7 ?? ?? df 6c 9b 86
                c7 ?? ?? 90 0c f0 44 }
      $cod2 = { c7 ?? ?? 21 69 4c 8d
                c7 ?? ?? b6 23 4d f7
                c7 ?? ?? 41 02 e8 b5
                c7 ?? ?? 99 4b 76 27 }
      $cod3 = { c7 ?? ?? 5a d7 d3 5f
                c7 ?? ?? 06 17 59 5f
                c7 ?? ?? 26 d5 65 a3
                c7 ?? ?? b7 eb c6 d0 }
      $cod4 = { c7 ?? ?? c5 01 ea 6c
                c7 ?? ?? 56 ba 91 33
                c7 ?? ?? c3 c2 6a 7d
                c7 ?? ?? 5e d4 ce 49 }
      $cod5 = { c7 ?? ?? ca fd a7 b3
                c7 ?? ?? e9 a4 f8 6d
                c7 ?? ?? 4b d0 05 07
                c7 ?? ?? 50 40 a7 12 }
      $cod6 = { c7 ?? ?? ce a1 a6 36
                c7 ?? ?? 56 fb 19 9d
                c7 ?? ?? d5 ab 90 52
                c7 ?? ?? 81 88 e8 7c }
      $cod7 = { c7 ?? ?? 6b 06 12 67
                c7 ?? ?? c7 dd eb 16
                c7 ?? ?? 03 68 12 8a
                c7 ?? ?? 93 3d 38 be }
      $cod8 = { c7 ?? ?? 56 f5 08 8f
                c7 ?? ?? 48 8e 50 99
                c7 ?? ?? 9e e6 cc ed
                c7 ?? ?? 1f 5d d6 aa }
      $cod9 = { c7 ?? ?? cd 67 96 f3
                c7 ?? ?? 24 ec b7 cf
                c7 ?? ?? 34 bc 9b c3
                c7 ?? ?? 8c e4 e6 49 }
   condition:
      uint16(0) == 0x5a4d and 1 of them
}
