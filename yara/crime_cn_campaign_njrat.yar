/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-08
   Identifier: Disclosed Chinese Malware Set - mostly NjRAT
   Reference: https://twitter.com/cyberintproject/status/961714165550342146
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule CN_disclosed_20180208_lsls {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"
   strings:
      $x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and $x1
}

rule CN_disclosed_20180208_c {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
      $x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
      $x3 = "www.upload.ee/image/" wide

      $s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s2 = "/Server.exe" fullword wide
      $s3 = "Executed As " fullword wide
      $s4 = "WmiPrvSE.exe" fullword wide
      $s5 = "Stub.exe" fullword ascii
      $s6 = "Download ERROR" fullword wide
      $s7 = "shutdown -r -t 00" fullword wide
      $s8 = "Select * From AntiVirusProduct" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
        1 of ($x*) or
        4 of them
      )
}

rule CN_disclosed_20180208_System3 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
   strings:
      $a1 = "WmiPrvSE.exe" fullword wide

      $s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
      $s2 = "Temporary Projects\\WmiPrvSE\\" ascii
      $s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and $a1 and 1 of ($s*)
}


rule CN_disclosed_20180208_Mal1 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "173d69164a6df5bced94ab7016435c128ccf7156145f5d26ca59652ef5dcd24e"
   strings:
      $x1 = "%SystemRoot%\\system32\\termsrvhack.dll" fullword ascii
      $x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii

      $a1 = "taskkill /f /im cmd.exe" fullword ascii
      $a2 = "taskkill /f /im mstsc.exe" fullword ascii
      $a3 = "taskkill /f /im taskmgr.exe" fullword ascii
      $a4 = "taskkill /f /im regedit.exe" fullword ascii
      $a5 = "taskkill /f /im mmc.exe" fullword ascii
      $s1 = "K7TSecurity.exe" fullword ascii
      $s2 = "ServUDaemon.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "28e3a58132364197d7cb29ee104004bf" or
        1 of ($x*) or
        3 of them
      )
}

rule CN_disclosed_20180208_KeyLogger_1 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"
   strings:
      $x2 = "Process already elevated." fullword wide
      $x3 = "GetKeyloggErLogsResponse" fullword ascii
      $x4 = "get_encryptedPassword" fullword ascii
      $x5 = "DoDownloadAndExecute" fullword ascii
      $x6 = "GetKeyloggeRLogs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_disclosed_20180208_Mal4 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e"
   strings:
      $s1 = "Microsoft .Net Framework COM+ Support" fullword ascii
      $s2 = "Microsoft .NET and Windows XP COM+ Integration with SOAP" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them and pe.exports("SPACE")
}

rule CN_disclosed_20180208_Mal5 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "24c05cd8a1175fbd9aca315ec67fb621448d96bd186e8d5e98cb4f3a19482af4"
      hash2 = "05696db46144dab3355dcefe0408f906a6d43fced04cb68334df31c6dfd12720"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "Server.exe" fullword ascii
      $s3 = "System.Windows.Forms.Form" fullword ascii
      $s4 = "Stub.Resources.resources" fullword ascii
      $s5 = "My.Computer" fullword ascii
      $s6 = "MyTemplate" fullword ascii
      $s7 = "Stub.My.Resources" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}
