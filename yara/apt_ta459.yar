
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-31
   Identifier: TA 459 - April 2017
   Reference: https://goo.gl/RLf9qU
*/

/* Rule Set ----------------------------------------------------------------- */

rule TA459_Malware_May17_1 {
   meta:
      description = "Detects TA459 related malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/RLf9qU"
      date = "2017-05-31"
      hash1 = "5fd61793d498a395861fa263e4438183a3c4e6f1e4f098ac6e97c9d0911327bf"
   strings:
      $s3 = "xtsewy" fullword ascii
      $s6 = "CW&mhAklnfVULL" ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 800KB and all of them )
}

rule TA459_Malware_May17_2 {
   meta:
      description = "Detects TA459 related malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/RLf9qU"
      date = "2017-05-31"
      hash1 = "4601133e94c4bc74916a9d96a5bc27cc3125cdc0be7225b2c7d4047f8506b3aa"
   strings:
      $a1 = "Mcutil.dll" fullword ascii
      $a2 = "mcut.exe" fullword ascii

      $s1 = "Software\\WinRAR SFX" fullword ascii
      $s2 = "AYou may need to run this self-extracting archive as administrator" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and all of ($a*) and 1 of ($s*) )
}