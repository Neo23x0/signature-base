/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-10
   Identifier: APT15 Report
   Reference: https://goo.gl/HZ5XMN
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT15_Malware_Mar18_RoyalCli {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      author = "Florian Roth"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
   strings:
      $s1 = "\\Release\\RoyalCli.pdb" ascii
      $s2 = "%snewcmd.exe" fullword ascii
      $s3 = "Run cmd error %d" fullword ascii
      $s4 = "%s~clitemp%08x.ini" fullword ascii
      $s5 = "run file failed" fullword ascii
      $s6 = "Cmd timeout %d" fullword ascii
      $s7 = "2 %s  %d 0 %d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule APT15_Malware_Mar18_RoyalDNS {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      author = "Florian Roth"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
   strings:
      $x1 = "del c:\\windows\\temp\\r.exe /f /q" fullword ascii
      $x2 = "%s\\r.exe" fullword ascii

      $s1 = "rights.dll" fullword ascii
      $s2 = "\"%s\">>\"%s\"\\s.txt" fullword ascii
      $s3 = "Nwsapagent" fullword ascii
      $s4 = "%s\\r.bat" fullword ascii
      $s5 = "%s\\s.txt" fullword ascii
      $s6 = "runexe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
        ( pe.exports("RunInstallA") and pe.exports("RunUninstallA") ) or
        1 of ($x*) or
        2 of them
      )
}

rule APT15_Malware_Mar18_BS2005 {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      author = "Florian Roth"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
   strings:
      $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
      $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii

      $a1 = "http://%s/content.html?id=%s" fullword ascii
      $a2 = "http://%s/main.php?ssid=%s" fullword ascii
      $a3 = "http://%s/webmail.php?id=%s" fullword ascii
      $a9 = "http://%s/error.html?tab=%s" fullword ascii

      $s1 = "%s\\~tmp.txt" fullword ascii
      $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
      $s3 = "DisableFirstRunCustomize" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         1 of ($x*) or
         2 of them
      )
}

rule APT15_Malware_Mar18_MSExchangeTool {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      author = "Florian Roth"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "16b868d1bef6be39f69b4e976595e7bd46b6c0595cf6bc482229dbb9e64f1bce"
   strings:
      $s1 = "\\Release\\EWSTEW.pdb" ascii
      $s2 = "EWSTEW.exe" fullword wide
      $s3 = "Microsoft.Exchange.WebServices.Data" fullword ascii
      $s4 = "tmp.dat" fullword wide
      $s6 = "/v or /t is null" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and all of them
}
