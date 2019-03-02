/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-08-01
   Identifier: FIN7
   Reference: https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule APT_FIN7_Strings_Aug18_1 {
   meta:
      description = "Detects strings from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"
   strings:
      $s1 = "&&call %a01%%a02% /e:jscript" ascii
      $s2 = "wscript.exe //b /e:jscript %TEMP%" ascii
      $s3 = " w=wsc@ript /b " ascii
      $s4 = "@echo %w:@=%|cmd" ascii
      $s5 = " & wscript //b /e:jscript"
   condition:
      1 of them
}

rule APT_FIN7_Sample_Aug18_2 {
   meta:
      description = "Detects FIN7 malware sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "1513c7630c981e4b1d0d5a55809166721df4f87bb0fac2d2b8ff6afae187f01d"
   strings:
      $x1 = "Description: C:\\Users\\oleg\\Desktop\\" wide
      $x2 = "/*|*| *  Copyright 2016 Microsoft, Industries.|*| *  All rights reserved.|*|" ascii
      $x3 = "32, 40, 102, 105, 108, 101, 95, 112, 97, 116, 104, 41, 41, 32" ascii
      $x4 = "83, 108, 101, 101, 112, 40, 51, 48, 48, 48, 41, 59, 102, 115" ascii
      $x5 = "80, 80, 68, 65, 84, 65, 37, 34, 41, 44, 115, 104, 101, 108, 108" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and 1 of them
}

rule APT_FIN7_MalDoc_Aug18_1 {
   meta:
      description = "Detects malicious Doc from FIN7 campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"
   strings:
      $s1 = "<photoshop:LayerText>If this document was downloaded from your email, please click  \"Enable editing\" from the yellow bar above" ascii
   condition:
      filesize < 800KB and 1 of them
}

rule APT_FIN7_Sample_Aug18_1 {
   meta:
      description = "Detects FIN7 samples mentioned in FireEye report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "a1e95ac1bb684186e9fb5c67f75c7c26ddc8b18ebfdaf061742ddf1675e17d55"
      hash2 = "dc645aae5d283fa175cf463a19615ed4d16b1d5238686245574d8a6a8b0fc8fa"
      hash3 = "eebbce171dab636c5ac0bf0fd14da0e216758b19c0ce2e5c572d7e6642d36d3d"
   strings:
      $s1 = "\\par var console=\\{\\};console.log=function()\\{\\};" fullword ascii
      $s2 = "616e64792d7063" ascii /* hex encoded string 'andy-pc' */

      $x1 = "0043003a005c00550073006500720073005c0061006e00640079005c004400650073006b0074006f0070005c0075006e00700072006f0074006500630074" ascii /* hex encoded string 'C:\Users\andy\Desktop\unprotect' */
      $x2 = "780065006300750074006500280022004f006e0020004500720072006f007200200052006500730075006d00650020004e006500780074003a0073006500" ascii /* hex encoded string 'xecute("On Error Resume Next:se' */
      $x3 = "\\par \\tab \\tab \\tab sh.Run \"powershell.exe -NoE -NoP -NonI -ExecutionPolicy Bypass -w Hidden -File \" & pToPSCb, 0, False" fullword ascii
      $x4 = "002e006c006e006b002d00000043003a005c00550073006500720073005c007400650073007400610064006d0069006e002e0054004500530054005c0044" ascii /* hex encoded string '.lnk-C:\Users\testadmin.TEST\D' */
      $x5 = "005c00550073006500720073005c005400450053005400410044007e0031002e005400450053005c0041007000700044006100740061005c004c006f0063" ascii /* hex encoded string '\Users\TESTAD~1.TES\AppData\Loc' */
      $x6 = "6c00690063006100740069006f006e002200220029003a00650078006500630075007400650020007700700072006f0074006500630074002e0041006300" ascii /* hex encoded string 'lication""):execute wprotect.Ac' */
      $x7 = "7374656d33325c6d736874612e657865000023002e002e005c002e002e005c002e002e005c00570069006e0064006f00770073005c005300790073007400" ascii /* hex encoded string 'stem32\mshta.exe#..\..\..\Windows\Syst' */
      $x8 = "\\par \\tab \\tab sh.Run \"%comspec% /c tasklist >\"\"\" & tpath & \"\"\" 2>&1\", 0, true" fullword ascii
      $x9 = "00720079007b006500760061006c0028002700770061006c006c003d004700650074004f0062006a0065006300740028005c005c0027005c005c00270027" ascii /* hex encoded string 'ry{eval('wall=GetObject(\\'\\''' */
      $x10 = "006e00640079005c004400650073006b0074006f0070005c0075006e006c006f0063006b002e0064006f0063002e006c006e006b" ascii /* hex encoded string 'ndy\Desktop\unlock.doc.lnk' */
   condition:
      uint16(0) == 0x5c7b and filesize < 3000KB and ( 1 of ($x*) or 2 of them )
}

rule APT_FIN7_EXE_Sample_Aug18_1 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "7f16cbe7aa1fbc5b8a95f9d123f45b7e3da144cb88db6e1da3eca38cf88660cb"
   strings:
      $s1 = "Manche Enterprises Limited0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_2 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"
   strings:
      $s1 = "constructor or from DllMain." fullword ascii
      $s2 = "Network Software Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_3 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"
   strings:
      $s1 = "cvzdfhtjkdhbfszngjdng" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_4 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "4b5405fc253ed3a89c770096a13d90648eac10a7fb12980e587f73483a07aa4c"
   strings:
      $s1 = "c:\\file.dat" fullword wide
      $s2 = "constructor or from DllMain." fullword ascii
      $s3 = "lineGetCallIDs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_5 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
   strings:
      $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
      $s3 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_6 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "1439d301d931c8c4b00717b9057b23f0eb50049916a48773b17397135194424a"
   strings:
      $s1 = "coreServiceShell.exe" fullword ascii
      $s2 = "PtSessionAgent.exe" fullword ascii
      $s3 = "TiniMetI.exe" fullword ascii
      $s4 = "PwmSvc.exe" fullword ascii
      $s5 = "uiSeAgnt.exe" fullword ascii
      $s7 = "LHOST:" fullword ascii
      $s8 = "TRANSPORT:" fullword ascii
      $s9 = "LPORT:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and (
         pe.exports("TiniStart") or
         4 of them
      )
}

rule APT_FIN7_EXE_Sample_Aug18_7 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "ce8ce35f85406cd7241c6cc402431445fa1b5a55c548cca2ea30eeb4a423b6f0"
   strings:
      $s1 = "libpng version" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_8 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
   strings:
      $s1 = "GetL3st3rr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_10 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"
   strings:
      /* "Copyright 1 - 19" */
      $c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
               00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43
               00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
               00 20 00 31 00 20 00 2D 00 20 00 31 00 39 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule APT_FIN7_Sample_EXE_Aug18_1 {
   meta:
      description = "Detects FIN7 Sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "608003c2165b0954f396d835882479f2504648892d0393f567e4a4aa90659bf9"
      hash2 = "deb62514704852ccd9171d40877c59031f268db917c23d00a2f0113dab79aa3b"
      hash3 = "16de81428a034c7b2636c4a875809ab62c9eefcd326b50c3e629df3b141cc32b"
      hash4 = "3937abdd1fd63587022ed540a31c58c87c2080cdec51dd24af3201a6310059d4"
      hash5 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
   strings:
      $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
      $s2 = "dx=%d, dy=%d" fullword ascii
      $s3 = "Error with JP2H box size" fullword ascii

      $co1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 2E 63 6F 64 65
               00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and all of ($s*)
      and $co1 at 0x015D
}
