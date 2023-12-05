
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-02
   Identifier: Fireball
   Reference: https://goo.gl/4pTkGQ
*/

/* Rule Set ----------------------------------------------------------------- */

rule Fireball_de_svr {
   meta:
      description = "Detects Fireball malware - file de_svr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "f964a4b95d5c518fd56f06044af39a146d84b801d9472e022de4c929a5b8fdcc"
      id = "29395239-66d8-5340-b884-9b8f036cc27f"
   strings:
      $s1 = "cmd.exe /c MD " fullword ascii
      $s2 = "rundll32.exe \"%s\",%s" fullword wide
      $s3 = "http://d12zpbetgs1pco.cloudfront.net/Weatherapi/shell" fullword wide
      $s4 = "C:\\v3\\exe\\de_svr_inst.pdb" fullword ascii
      $s5 = "Internet Connect Failed!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 4 of them )
}

rule Fireball_lancer {
   meta:
      description = "Detects Fireball malware - file lancer.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "7d68386554e514f38f98f24e8056c11c0a227602ed179d54ed08f2251dc9ea93"
      id = "2209bcb4-74a6-5c39-962c-ccd4ce62619e"
   strings:
      $x1 = "\\instlsp\\Release\\Lancer.pdb" ascii
      $x2 = "lanceruse.dat" fullword wide

      $s1 = "Lancer.dll" fullword ascii
      $s2 = "RunDll32.exe \"" fullword wide
      $s3 = "Micr.dll" fullword wide
      $s4 = "AG64.dll" fullword wide
      $s5 = "\",Start" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 6 of them )
}

rule QQBrowser {
   meta:
      description = "Not malware but suspicious browser - file QQBrowser.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      score = 50
      hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"
      id = "457507c5-0411-5d72-891b-ae3e428ea2d6"
   strings:
      $s1 = "TerminateProcessWithoutDump" fullword ascii
      $s2 = ".Downloader.dll" fullword wide
      $s3 = "Software\\Chromium\\BrowserCrashDumpAttempts" fullword wide
      $s4 = "QQBrowser_Broker.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule chrome_elf {
   meta:
      description = "Detects Fireball malware - file chrome_elf.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "e4d4f6fbfbbbf3904ca45d296dc565138a17484c54aebbb00ba9d57f80dfe7e5"
      id = "8680d5b5-e26f-5a3f-aeab-b965afe91027"
   strings:
      $x2 = "schtasks /Create /SC HOURLY /MO %d /ST 00:%02d:00 /TN \"%s\" /TR \"%s\" /RU \"SYSTEM\"" fullword wide
      $s6 = "aHR0cDovL2R2Mm0xdXVtbnNndHUuY2xvdWRmcm9udC5uZXQvdjQvZ3RnLyVzP2FjdGlvbj12aXNpdC5jaGVsZi5pbnN0YWxs" fullword ascii /* base64 encoded string 'http://dv2m1uumnsgtu.cloudfront.net/v4/gtg/%s?action=visit.chelf.install' */
      $s7 = "QueryInterface call failed for IExecAction: %x" fullword ascii
      $s10 = "%s %s,Rundll32_Do %s" fullword wide
      $s13 = "Failed to create an instance of ITaskService: %x" fullword ascii
      $s16 = "Rundll32_Do" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them )
}

rule Fireball_regkey {
   meta:
      description = "Detects Fireball malware - file regkey.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      modified = "2022-12-21"
      hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"
      id = "6e22bb93-8c8b-510f-a9e4-6e57c392c2ae"
   strings:
      $s1 = "\\WinMain\\Release\\WinMain.pdb" ascii
      $s2 = "ScreenShot" fullword wide
      $s3 = "WINMAIN" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule Fireball_winsap {
   meta:
      description = "Detects Fireball malware - file winsap.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"
      id = "e68e7738-f325-5b73-9e61-4e2413b7b7be"
   strings:
      $s1 = "aHR0cDovL2" ascii /* base64 encoded string 'http://d3i1asoswufp5k.cloudfront.net/v4/gtg/%s?action=visit.winsap.work&update3=version,%s' */
      $s2 = "%s\\svchost.exe -k %s" fullword wide
      $s3 = "\\SETUP.dll" wide
      $s4 = "WinSAP.dll" fullword ascii
      $s5 = "Error %u in WinHttpQueryDataAvailable." fullword ascii
      $s6 = "UPDATE OVERWRITE" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them )
}

rule Fireball_archer {
   meta:
      description = "Detects Fireball malware - file archer.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      modified = "2022-12-21"
      hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"
      id = "16bb95c1-af69-5688-8999-f097d02d2ffc"
   strings:
      $x1 = "\\archer_lyl\\Release\\Archer_Input.pdb" ascii

      $s1 = "Archer_Input.dll" fullword ascii
      $s2 = "InstallArcherSvc" fullword ascii
      $s3 = "%s_%08X" fullword wide
      $s4 = "d\\\\.\\PhysicalDrive%d" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( $x1 or 3 of them )
}

rule clearlog {
   meta:
      description = "Detects Fireball malware - file clearlog.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "14093ce6d0fe8ab60963771f48937c669103842a0400b8d97f829b33c420f7e3"
      id = "3eb58a7a-b04d-52c2-8c3c-c149da8d4aa8"
   strings:
      $x1 = "\\ClearLog\\Release\\logC.pdb" ascii

      $s1 = "C:\\Windows\\System32\\cmd.exe /c \"\"" fullword wide
      $s2 = "logC.dll" fullword ascii
      $s3 = "hhhhh.exe" fullword wide
      $s4 = "ttttt.exe" fullword wide
      $s5 = "Logger Name:" fullword ascii
      $s6 = "cle.log.1" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 or 2 of them )
}

rule Fireball_gubed {
   meta:
      description = "Detects Fireball malware - file gubed.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      modified = "2022-12-21"
      hash1 = "e3f69a1fb6fcaf9fd93386b6ba1d86731cd9e5648f7cff5242763188129cd158"
      id = "cba2913f-4d9a-5925-ad9a-f5815a635291"
   strings:
      $x1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MRT.exe" fullword wide
      $x2 = "tIphlpapi.dll" fullword wide
      $x3 = "http://%s/provide?clients=%s&reqs=visit.startload" fullword wide
      $x4 = "\\Gubed\\Release\\Gubed.pdb" ascii
      $x5 = "d2hrpnfyb3wv3k.cloudfront.net" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}
