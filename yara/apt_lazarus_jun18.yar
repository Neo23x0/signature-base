/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-01
   Identifier: Lazarus Group
   Reference: https://twitter.com/DrunkBinary/status/1002587521073721346
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_Lazarus_Dropper_Jun18_1 {
   meta:
      description = "Detects Lazarus Group Dropper"
      author = "Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01"
      hash1 = "086a50476f5ceee4b10871c1a8b0a794e96a337966382248a8289598b732bd47"
      hash2 = "9f2d4fd79d3c68270102c4c11f3e968c10610a2106cbf1298827f8efccdd70a9"
   strings:
      $s1 = /%s\\windows10-kb[0-9]{7}.exe/ fullword ascii
      $s2 = "EYEJIW" fullword ascii
      $s3 = "update" fullword wide /* Goodware String - occured 254 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and (
        pe.imphash() == "fcac768eff9896d667a7c706d70712ce" or
        all of them
      )
}

rule APT_Lazarus_RAT_Jun18_1 {
   meta:
      description = "Detects Lazarus Group RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01"
      hash1 = "c10363059c57c52501c01f85e3bb43533ccc639f0ea57f43bae5736a8e7a9bc8"
      hash2 = "e98991cdd9ddd30adf490673c67a4f8241993f26810da09b52d8748c6160a292"
   strings:
      $a1 = "www.marmarademo.com/include/extend.php" fullword ascii
      $a2 = "www.33cow.com/include/control.php" fullword ascii
      $a3 = "www.97nb.net/include/arc.sglistview.php" fullword ascii

      $c1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"example.dat\"" fullword ascii
      $c2 = "Content-Disposition: form-data; name=\"file1\"; filename=\"pratice.pdf\"" fullword ascii
      $c3 = "Content-Disposition: form-data; name=\"file1\"; filename=\"happy.pdf\"" fullword ascii
      $c4 = "Content-Disposition: form-data; name=\"file1\"; filename=\"my.doc\"" fullword ascii
      $c5 = "Content-Disposition: form-data; name=\"board_id\"" fullword ascii

      $s1 = "Winhttp.dll" fullword ascii
      $s2 = "Wsock32.dll" fullword ascii
      $s3 = "WM*.tmp" fullword ascii
      $s4 = "FM*.tmp" fullword ascii
      $s5 = "Cache-Control: max-age=0" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         1 of ($a*) or
         2 of ($c*) or
         4 of them
      )
}

rule APT_Lazarus_RAT_Jun18_2 {
   meta:
      description = "Detects Lazarus Group RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01"
      hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
   strings:
      $s1 = "\\KB\\Release\\" ascii
      $s3 = "KB, Version 1.0" fullword wide
      $s4 = "TODO: (c) <Company name>.  All rights reserved." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}