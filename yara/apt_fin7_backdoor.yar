
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-04
   Identifier: FIN7
   Reference: https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor
*/

/* Rule Set ----------------------------------------------------------------- */

rule FIN7_Dropper_Aug17 {
   meta:
      description = "Detects Word Dropper from Proofpoint FIN7 Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
      date = "2017-08-04"
      hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
      hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
      id = "4929dff6-9f33-5d22-b560-c2195440a1cc"
   strings:
      $x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii

      $s1 = "Scripting.FileSystemObject$" fullword ascii
      $s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
      $s3 = "Project.ThisDocument.AutoOpen" fullword wide
      $s4 = "\\system3" ascii
      $s5 = "ShellV" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of ($x*) or all of ($s*) )
}

rule FIN7_Backdoor_Aug17 {
   meta:
      description = "Detects Word Dropper from Proofpoint FIN7 Report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
      date = "2017-08-04"
      id = "906daf88-520b-57b5-825e-29f060b43183"
   strings:
      $x1 = "wscript.exe //b /e:jscript C:\\Users\\" ascii
      $x2 = "wscript.exe /b /e:jscript C:\\Users\\" ascii
      $x3 = "schtasks /Create /f /tn \"GoogleUpdateTaskMachineSystem\" /tr \"wscript.exe" ascii nocase
      $x4 = "schtasks /Delete /F /TN \"\"GoogleUpdateTaskMachineCore" ascii nocase
      $x5 = "schtasks /Delete /F /TN \"GoogleUpdateTaskMachineCore" ascii nocase
      $x6 = "wscript.exe //b /e:jscript %TMP%\\debug.txt" ascii

      $s1 = "/?page=wait" fullword ascii

      $a1 = "autoit3.exe" fullword ascii
      $a2 = "dumpcap.exe" fullword ascii
      $a3 = "tshark.exe" fullword ascii
      $a4 = "prl_cc.exe" fullword ascii

      $v1 = "vmware" fullword ascii
      $v2 = "PCI\\\\VEN_80EE&DEV_CAFE" fullword ascii
      $v3 = "VMWVMCIHOSTDEV" fullword ascii

      $c1 = "apowershell" fullword ascii
      $c2 = "wpowershell" fullword ascii
      $c3 = "get_passwords" fullword ascii
      $c4 = "kill_process" fullword ascii
      $c5 = "get_screen" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and
         (
            1 of ($x*) or
            all of ($a*) or
            all of ($v*) or
            3 of ($c*)
         )
      ) or 5 of them
}
