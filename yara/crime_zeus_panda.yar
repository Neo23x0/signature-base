/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-04
   Identifier: Zeus Panda
   Reference: https://cyberwtf.files.wordpress.com/2017/07/panda-whitepaper.pdf
*/

/* Rule Set ----------------------------------------------------------------- */

rule Zeus_Panda {
   meta:
      description = "Detects ZEUS Panda Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://cyberwtf.files.wordpress.com/2017/07/panda-whitepaper.pdf"
      date = "2017-08-04"
      hash1 = "bd956b2e81731874995b9b92e20f75dbf67ac5f12f9daa194525e1b673c7f83c"
      id = "2786b1e0-37af-5595-a24b-56ef3cb928a7"
   strings:
      $x1 = "SER32.dll" fullword ascii
      $x2 = "/c start \"\" \"%s\"" fullword wide
      $x3 = "del /F \"%s\"" fullword ascii

      $s1 = "bcdfghklmnpqrstvwxz" fullword ascii
      $s2 = "=> -,0;" fullword ascii
      $s3 = "Yahoo! Slurp" fullword ascii
      $s4 = "ZTNHGET ^&" fullword ascii
      $s5 = "MSIE 9" fullword ascii
      $s6 = "%s%08x.%s" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( 2 of ($x*) or 4 of them )
}