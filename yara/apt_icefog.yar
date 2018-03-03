/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-26
   Identifier: IceFog
   Reference: https://twitter.com/ClearskySec/status/968104465818669057
*/

/* Rule Set ----------------------------------------------------------------- */

rule IceFog_Malware_Feb18_1 {
   meta:
      description = "Detects IceFog malware"
      author = "Florian Roth"
      reference = "https://twitter.com/ClearskySec/status/968104465818669057"
      date = "2018-02-26"
      hash1 = "480373cffc4e60aa5be2954a156e37d689b92e6e33969958230f2ce59d30b9ec"
   strings:
      $s1 = "cmd /c %c%s%c" fullword ascii
      $s2 = "temp.bat" fullword ascii
      $s3 = "c:\\windows\\debug\\wia\\help" fullword wide
      $s4 = "/getorder.aspx?hostname=" fullword wide
      $s5 = "\\filecfg_temp.dat" fullword wide
      $s6 = "Unknown operating system " fullword wide
      $s7 = "kastygost.compress.to" fullword wide
      $s8 = "/downloads/" fullword wide
      $s9 = "\\key.dat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them
}
