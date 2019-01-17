/* This is an extract from THOR's anomaly detection rule set */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-11
   Identifier: PowerShell Anomalies
   Reference: https://twitter.com/danielhbohannon/status/905096106924761088
*/

rule PowerShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated PowerShell hacktools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
      date = "2017-08-11"
      score = 70
   strings:
      // first detect 'powershell' keyword case insensitive
      $s1 = "powershell" fullword nocase ascii wide
      // define the normal cases
      $sr1 = /(powershell|Powershell|PowerShell|POWERSHELL|powerShell)/ fullword ascii wide
      // define the normal cases
      $sn1 = "powershell" fullword ascii wide
      $sn2 = "Powershell" fullword ascii wide
      $sn3 = "PowerShell" fullword ascii wide
      $sn4 = "POWERSHELL" fullword ascii wide
      $sn5 = "powerShell" fullword ascii wide

      // PowerShell with \x19\x00\x00
      $a1 = "wershell -e " nocase wide ascii
      // expected casing
      $an1 = "wershell -e " wide ascii
      $an2 = "werShell -e " wide ascii

      // adding a keyword with a sufficent length and relevancy
      $k1 = "-noprofile" fullword nocase ascii wide
      // define normal cases
      $kn1 = "-noprofile" ascii wide
      $kn2 = "-NoProfile" ascii wide
      $kn3 = "-noProfile" ascii wide
      $kn4 = "-NOPROFILE" ascii wide
      $kn5 = "-Noprofile" ascii wide

      $fp1 = "Microsoft Code Signing" ascii fullword
      $fp2 = "Microsoft Corporation" ascii
   condition:
      filesize < 800KB and (
         // find all 'powershell' occurances and ignore the expected cases
         ( #s1 < 3 and #sr1 > 0 and #s1 > #sr1 ) or
         ( $s1 and not 1 of ($sn*) ) or
         ( $a1 and not 1 of ($an*) ) or
         // find all '-norpofile' occurances and ignore the expected cases
         ( $k1 and not 1 of ($kn*) )
      ) and not 1 of ($fp*)
}


rule WScriptShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated wscript.shell commands"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-11"
      score = 60
   strings:
      // first detect powershell keyword case insensitive
      $s1 = "WScript.Shell\").Run" nocase ascii wide
      // define the normal cases
      $sn1 = "WScript.Shell\").Run" ascii wide
      $sn2 = "wscript.shell\").run" ascii wide
      $sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
      $sn4 = "Wscript.Shell\").Run" ascii wide
      $sn5 = "WScript.Shell\").Run" ascii wide
      $sn6 = "WScript.shell\").Run" ascii wide
   condition:
      filesize < 800KB and
      ( $s1 and not 1 of ($sn*) )
}
