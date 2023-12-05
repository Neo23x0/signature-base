/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-23
   Identifier: Sofacy Malware
   Reference: http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Sofacy_Oct17_1 {
   meta:
      description = "Detects Sofacy malware reported in October 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
      date = "2017-10-23"
      hash1 = "522fd9b35323af55113455d823571f71332e53dde988c2eb41395cf6b0c15805"
      id = "6896dcf3-e422-5a40-bc1e-d1f35ae95c14"
   strings:
      $x1 = "%localappdata%\\netwf.dll" fullword wide
      $x2 = "set path = \"%localappdata%\\netwf.dll\"" fullword ascii
      $x3 = "%localappdata%\\netwf.bat" fullword wide
      $x4 = "KlpSvc.dll" fullword ascii

      /* used for generic approach */
      $g1 = "set path = \"%localappdata%\\" ascii
      $g2 = "%localappdata%\\" wide

      $s1 = "start rundll32.exe %path %,#1a" fullword ascii

      $s2 = "gshell32" fullword wide
      $s3 = "s - %lu" fullword ascii
      $s4 = "be run i" fullword ascii
      $s5 = "ingToBinhary" fullword ascii
      $s6 = "%j%Xjs" fullword ascii
      $s7 = "if NOT exist %path % (exit)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
         pe.imphash() == "a2d1be6502b4b3c28959a4fb0196ea45" or
         pe.exports("KlpSvc") or
         ( 1 of ($x*) or 4 of them ) or
         ( $s1 and all of ($g*) )
      )
}

rule Sofacy_Oct17_2 {
   meta:
      description = "Detects Sofacy malware reported in October 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
      date = "2017-10-23"
      hash1 = "ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"
      id = "c820eab0-9b64-5718-8681-a4f515ee462b"
   strings:
      $x1 = "netwf.dll" fullword wide

      $s1 = "%s - %s - %2.2x" fullword wide
      $s2 = "%s - %lu" fullword ascii
      $s3 = "%s \"%s\", %s" fullword wide
      $s4 = "%j%Xjsf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and (
            pe.imphash() == "13344e2a717849489bcd93692f9646f7" or
            ( 4 of them )
         )
      ) or ( all of them )
}
