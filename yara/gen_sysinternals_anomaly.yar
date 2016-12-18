/*
	Yara Rule Set
	Author: FLorian Roth
	Date: 2016-12-08
	Identifier: Modified SysInternals Tools
*/

/* Rule Set ----------------------------------------------------------------- */

rule SysInternals_Tool_Anomaly {
   meta:
      description = "SysInternals Tool Anomaly - does not contain Mark Russinovich as author"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-12-06"
   strings:
      $s1 = "Software\\Sysinternals\\%s" fullword ascii

      $n1 = "Mark Russinovich" wide

      $nfp1 = "<<<Obsolete>>>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $s1 and not $n1 and not 1 of ($nfp*) )
}
