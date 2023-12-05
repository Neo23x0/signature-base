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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "Internal Research"
      date = "2016-12-06"
      id = "b676726b-7ecd-52ed-bdec-3d81b7596246"
   strings:
      $s1 = "Software\\Sysinternals\\%s" fullword ascii

      $n1 = "Mark Russinovich" wide ascii

      $nfp1 = "<<<Obsolete>>>" fullword wide
      $nfp2 = "BGInfo - Wallpaper text configurator" wide
      $nfp3 = "usage: movefile [source] [dest]" wide
      $nfp4 = "LoadOrder information has been copied" wide
      $nfp5 = "Cache working set cleared" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $s1 and not $n1 and not 1 of ($nfp*) )
}
