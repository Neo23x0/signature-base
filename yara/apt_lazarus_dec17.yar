
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-20
   Identifier: Lazarus malware
   Reference: https://www.proofpoint.com/us/threat-insight/post/north-korea-bitten-bitcoin-bug-financially-motivated-campaigns-reveal-new
*/

/* Rule Set ----------------------------------------------------------------- */

rule Lazarus_Dec_17_1 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"
      id = "f195ebf0-d7af-58e8-a544-769a0c8b628b"
   strings:
      $s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
      $s2 = "HHA Version 4." ascii
      $s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F
              62 65 20 49 6D 61 67 65 52 65 61 64 79 71 }
      $s4 = "bUEeYE" fullword ascii
   condition:
      uint16(0) == 0x5449 and filesize < 4000KB and all of them
}

rule Lazarus_Dec_17_2 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "cbebafb2f4d77967ffb1a74aac09633b5af616046f31dddf899019ba78a55411"
      hash2 = "9ca3e56dcb2d1b92e88a0d09d8cab2207ee6d1f55bada744ef81e8b8cf155453"
      id = "45127fb5-0f70-5140-acd9-46147d365dfe"
   strings:
      $s1 = "SkypeSetup.exe" fullword wide
      $s2 = "%s\\SkypeSetup.exe" fullword ascii
      $s3 = "Skype Technologies S.A." fullword wide

      $a1 = "Microsoft Code Signing PCA" ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and (
        all of ($s*) and not $a1
      )
}

rule Lazarus_Dec_17_4 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
      hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"
      id = "fbdc6287-c177-53b5-83dd-979936f65192"
   strings:
      $s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii
   condition:
      filesize < 9KB and 1 of them
}

rule Lazarus_Dec_17_5 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"
      id = "33bd8c08-123e-5a8e-b5dc-02af7291addc"
   strings:
      $x1 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
      $x2 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
      $x3 = "[String]$PS_PATH = \"C:\\\\Users\\\\Public\\\\Documents\\\\ProxyAutoUpdate.ps1\";" fullword ascii
      $x4 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
      $x5 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
      $x6 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
      $x7 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
      $x8 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii
   condition:
      filesize < 500KB and 1 of them
}