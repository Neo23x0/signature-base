/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Winnti MS Report
*/

/* Rule Set ----------------------------------------------------------------- */

rule Winnti_fonfig {
   meta:
      description = "Winnti sample - file fonfig.exe"
      author = "Florian Roth"
      reference = "https://goo.gl/VbvJtL"
      date = "2017-01-25"
      hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
   strings:
      $s1 = "mciqtz.exe" fullword wide
      $s2 = "knat9y7m" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Winnti_NlaifSvc {
   meta:
      description = "Winnti sample - file NlaifSvc.dll"
      author = "Florian Roth"
      reference = "https://goo.gl/VbvJtL"
      date = "2017-01-25"
      hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
   strings:
      $x1 = "cracked by ximo" ascii

      $s1 = "Yqrfpk" fullword ascii
      $s2 = "IVVTOC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}
