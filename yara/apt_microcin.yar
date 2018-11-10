/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-26
   Identifier: Microcin
   Reference: https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Microcin_Sample_1 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "49816eefcd341d7a9c1715e1f89143862d4775ba4f9730397a1e8529f5f5e200"
      hash2 = "a73f8f76a30ad5ab03dd503cc63de3a150e6ab75440c1060d75addceb4270f46"
      hash3 = "9dd9bb13c2698159eb78a0ecb4e8692fd96ca4ecb50eef194fa7479cb65efb7c"
   strings:
      $s1 = "e Class Descriptor at (" fullword ascii
      $s2 = ".?AVCAntiAntiAppleFrameRealClass@@" fullword ascii
      $s3 = ".?AVCAntiAntiAppleFrameBaseClass@@" fullword ascii
      $s4 = ".?AVCAppleBinRealClass@@" fullword ascii
      $s5 = ".?AVCAppleBinBaseClass@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and (
            4 of them or
            pe.imphash() == "897077ca318eaf629cfe74569f10e023"
         )
      )
}

rule Microcin_Sample_2 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
   strings:
      $s2 = "[Pause]" fullword ascii
      $s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_3 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
   strings:
      $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
      $s2 = "test, Version 1.0" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_4 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"
   strings:
      $s1 = "cmd /c dir /a /s \"%s\" > \"%s\"" fullword wide
      $s2 = "ini.dat" fullword wide
      $s3 = "winupdata" fullword wide

      $f1 = "%s\\(%08x%08x)%s" fullword wide
      $f2 = "%s\\d%08x\\d%08x.db" fullword wide
      $f3 = "%s\\u%08x\\u%08x.db" fullword wide
      $f4 = "%s\\h%08x\\h%08x.db" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or 5 of them )
}

rule Microcin_Sample_5 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
   strings:
      $x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
      $x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
      $x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
      $x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
      $x5 = "No password found!" fullword ascii
      $x7 = "Can not found the Password Dictoonary file! " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them ) or 2 of them
}

rule Microcin_Sample_6 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
      hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
   strings:
      $s1 = "** ERROR ** %s: %s" fullword ascii
      $s2 = "TEMPDATA" fullword wide
      $s3 = "Bruntime error " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}
