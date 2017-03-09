
/*
   Yara Rule Set
   Author: Kaspersky
   Date: 2017-03-07
   Identifier: Stone Drill Report by Kaspersky
*/

import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
   meta:
      copyright = "Kaspersky Lab"
      description = "Generic detection for samples that enumerate files with encrypted resource called 101"
      hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
      hash = "c843046e54b755ec63ccb09d0a689674"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      version = "1.4"
   strings:
      $mz = "This program cannot be run in DOS mode."
      $a1 = "FindFirstFile" ascii wide nocase
      $a2 = "FindNextFile" ascii wide nocase
      $a3 = "FindResource" ascii wide nocase
      $a4 = "LoadResource" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      all of them and
      filesize < 700000 and
      pe.number_of_sections > 4 and
      pe.number_of_resources > 1 and pe.number_of_resources < 15 and
      for any i in (0..pe.number_of_resources - 1):
         (
            (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and
            pe.resources[i].id == 101 and
            pe.resources[i].length > 20000 and
            pe.resources[i].language == 0 and
            not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
         )
}

rule StoneDrill_main_sub {
   meta:
      author = "Kaspersky Lab"
      description = "Rule to detect StoneDrill (decrypted) samples"
      hash1 = "d01781f1246fd1b64e09170bd6600fe1"
      hash2 = "ac3c25534c076623192b9381f926ba0d"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      version = "1.0"
   strings:
      $code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF 30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}
   condition:
      uint16(0) == 0x5A4D and $code and filesize < 5000000
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-07
   Identifier: Stone Drill Report by Kaspersky
*/

rule StoneDrill_BAT_1 {
   meta:
      author = "Florian Roth"
      description = "Rule to detect Batch file from StoneDrill report"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
   strings:
      $s1 = "set u100=" ascii
      $s2 = "set u200=service" ascii fullword
      $s3 = "set u800=%~dp0" ascii fullword
      $s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
      $s5 = "%\" start /b %systemroot%\\system32\\%" ascii
   condition:
      uint32(0) == 0x68636540 and 2 of them and filesize < 500
}

rule StoneDrill_Service_Install {
   meta:
      author = "Florian Roth"
      description = "Rule to detect Batch file from StoneDrill report"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
   strings:
      $s1 = "127.0.0.1 >nul && sc config" ascii
      $s2 = "LocalService\" && ping -n" ascii fullword
      $s3 = "127.0.0.1 >nul && sc start" ascii fullword
      $s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii
   condition:
      2 of them and filesize < 500
}

rule StoneDrill_ntssrvr32 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
   strings:
      $s1 = "g\\system32\\" fullword wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule StoneDrill_Malware_2 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      hash1 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
   strings:
      $s1 = "cmd /c WMIC Process Call Create \"C:\\Windows\\System32\\Wscript.exe //NOLOGO " fullword wide
      $s2 = "C:\\ProgramData\\InternetExplorer" fullword wide
      $s3 = "WshShell.CopyFile \"" fullword wide
      $s4 = "Abd891.tmp" fullword wide
      $s5 = "Set WshShell = Nothing" fullword wide
      $s6 = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32" fullword ascii
      $s7 = "\\FileInfo.txt" fullword wide

      $x1 = "C-PDI-C-Cpy-T.vbs" fullword wide
      $x2 = "C-Dlt-C-Org-T.vbs" fullword wide
      $x3 = "C-PDC-C-Cpy-T.vbs" fullword wide
      $x4 = "AC-PDC-C-Cpy-T.vbs" fullword wide
      $x5 = "C-Dlt-C-Trsh-T.tmp" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 3 of ($s*) ) ) or 5 of them
}

rule StoneDrill {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      super_rule = 1
      hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
      hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
      hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
   strings:
      $x1 = "C-Dlt-C-Trsh-T.tmp" fullword wide
      $x2 = "C-Dlt-C-Org-T.vbs" fullword wide

      $s1 = "Hello dear" fullword ascii
      $s2 = "WRZRZRAR" fullword ascii

      $opa1 = { 66 89 45 d8 6a 64 ff }
      $opa2 = { 8d 73 01 90 0f bf 51 fe }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) or ( all of ($op*) and all of ($s*) )
}

rule StoneDrill_VBS_1 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
   strings:
      $x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
      $x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii

      $s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
      $s2 = "WshShell.DeleteFile \"%temp%\\" ascii
      $s3 = "WScript.Sleep(10 * 1000)" fullword ascii
      $s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
      $s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii
   condition:
      ( filesize < 1KB and 1 of ($x*) or 2 of ($s*) )
}
