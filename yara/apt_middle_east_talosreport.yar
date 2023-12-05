/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-07
   Identifier: ME Campaign Talos Report
   Reference: http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ME_Campaign_Malware_1 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      hash1 = "1176642841762b3bc1f401a5987dc55ae4b007367e98740188468642ffbd474e"
      id = "7c844c5c-caf0-5968-ac1a-72886fcf97cf"
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and (
        pe.imphash() == "618f76eaf4bd95c690d43e84d617efe9"
      )
}

rule ME_Campaign_Malware_2 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      hash1 = "76a9b603f1f901020f65358f1cbf94c1a427d9019f004a99aa8bff1dea01a881"
      id = "a0beec30-62ff-54c3-ab62-c54454b89f8d"
   strings:
      $s1 = "QuickAssist.exe" fullword wide
      $s2 = "<description>Microsoft Modern Sharing Solution</description>" fullword ascii
      $s3 = "GBEWCWA" fullword ascii
      $s4 = "name=\"QuickAssist\" " fullword ascii
      $s5 = "Cimzal" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
        pe.imphash() == "b06055e6cc2a804111ab6964df1ca4ae" or
        4 of them
      )
}

rule ME_Campaign_Malware_3 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
      id = "d8bfd426-ff42-5332-8206-67a558509494"
   strings:
      $x1 = "objWShell.Run \"powershell.exe -ExecutionPolicy Bypass -File \"\"%appdata%\"\"\\sys.ps1\", 0 " fullword ascii
      $x2 = "objFile.WriteLine \"New-Item -Path \"\"$ENV:APPDATA\\Microsoft\\Templates\"\" -ItemType Directory -Force }\" " fullword ascii
      $x3 = "objFile.WriteLine \"$path = \"\"$ENV:APPDATA\\Microsoft\\Templates\\Report.doc\"\"\" " fullword ascii
      $s4 = "File=appData & \"\\sys.ps1\"" fullword ascii
   condition:
      uint16(0) == 0x6553 and filesize < 400KB and 1 of them
}

rule ME_Campaign_Malware_4 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      hash1 = "c5bfb5118a999d21e9f445ad6ccb08eb71bc7bd4de9e88a41be9cf732156c525"
      id = "1ff83ac6-e3f1-55e2-a811-e526b8235c78"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "fb7da233a35ac523d6059fff543627ab"
}

rule ME_Campaign_Malware_5 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      modified = "2022-08-18"
      hash1 = "d49e9fdfdce1e93615c406ae13ac5f6f68fb7e321ed4f275f328ac8146dd0fc1"
      hash2 = "e66af059f37bdd35056d1bb6a1ba3695fc5ce333dc96b5a7d7cc9167e32571c5"
      id = "241a4236-2688-5920-87f7-eed33963ec60"
   strings:
      $s1 = "D:\\me\\do\\do\\obj\\" ascii
      $s2 = "Select * from Win32_ComputerSystem" fullword wide
      $s3 = "Get_Antivirus" fullword ascii
      $s4 = "{{\"id\":\"{0}\",\"user\":\"{1}\",\"path\":\"{2}\"}}" fullword wide
      $s5 = "update software online" fullword wide
      $s6 = "time.nist.gov" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and 5 of them or all of them
}
