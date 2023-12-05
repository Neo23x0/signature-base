/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-09
   Identifier: Cobalt Gang
   Reference: Internal Research
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

/* Removed Beacon rules - only in THOR */

rule CobaltStrike_CN_Group_BeaconDropper_Aug17 {
   meta:
      description = "Detects Script Dropper of Cobalt Gang used in August 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-09"
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
      hash2 = "1c845bb0f6b9a96404af97dcafdc77f1629246e840c01dd9f1580a341f554926"
      hash3 = "6206e372870ea4f363be53557477f9748f1896831a0cdef3b8450a7fb65b86e1"
      id = "5631b0bc-9e25-524a-9003-73779fd492f7"
   strings:
      $x1 = "WriteLine(\"(new ActiveXObject('WScript.Shell')).Run('cmd /c c:/" ascii
      $x2 = "WriteLine(\" (new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" ascii
      $x3 = "sh.Run(env('cmd /c set > %temp%" ascii
      $x4 = "sh.Run('regsvr32 /s /u /i:" ascii
      $x5 = ".Get('Win32_ScheduledJob').Create('regsvr32 /s /u /i:" ascii
      $x6 = "scrobj.dll','********" ascii
      $x7 = "www.thyssenkrupp-marinesystems.org" fullword ascii
      $x8 = "f.WriteLine(\" tLnk=env('%tmp%/'+lnkName+'.lnk');\");" fullword ascii
      $x9 = "lnkName='office 365'; " fullword ascii
      $x10 = ";sh=x('WScript.Shell');" ascii
   condition:
      ( filesize < 200KB and 1 of them )
}

rule CobaltGang_Malware_Aug17_1 {
   meta:
      description = "Detects a Cobalt Gang malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
      date = "2017-08-09"
      hash1 = "6d70673b723f338b3febc9f1d69463bdd4775539cb92b5a5d8fccc0d977fa2f0"
      id = "56c6f4f8-ccf5-5665-ac21-67f0a9b67cf1"
   strings:
      $s1 = "ServerSocket.EXE" fullword wide
      $s2 = "Incorrect version of WS2_32.dll found" fullword ascii
      $s3 = "Click 'Connect' to Connect to the Server.  'Disconnect' to disconnect from server." fullword wide
      $s4 = "Click 'Start' to start the Server.  'Stop' to Stop it." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule CobaltGang_Malware_Aug17_2 {
   meta:
      description = "Detects a Cobalt Gang malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
      date = "2017-08-09"
      hash1 = "80791d5e76782cc3cd14f37f351e33b860818784192ab5b650f1cdf4f131cf72"
      id = "2839c119-0fa4-51f0-a406-5d381cc594a2"
   strings:
      $s1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule MAL_CRIME_CobaltGang_Malware_Oct19_1 {
   meta:
      description = "Detects CobaltGang malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxsh4d0w/status/1187353649015611392"
      date = "2019-10-24"
      hash1 = "72125933265f884ceb8ab64ab303ea76aaeb7877faee8976d398acd0d0b7356b"
      hash2 = "893339624602c7b3a6f481aed9509b53e4e995d6771c72d726ba5a6b319608a7"
      hash3 = "3c34bbf641df25f9accd05b27b9058e25554fdfea0e879f5ca21ffa460ad2b01"
      id = "95c16016-b09b-56f3-b5a4-fca18ac70ad5"
   strings:
      $op_a1 = { 0f 44 c2 eb 0a 31 c0 80 fa 20 0f 94 c0 01 c0 5d }

      $op_b1 = { 89 e5 53 8b 55 08 8b 4d 0c 8a 1c 01 88 1c 02 83 }
      $op_b2 = { 89 e5 53 8b 55 08 8b 45 0c 8a 1c 0a 88 1c 08 83 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and (
         pe.imphash() == "d1e3f8d02cce09520379e5c1e72f862f" or
         pe.imphash() == "8e26df99c70f79cb8b1ea2ef6f8e52ac" or
         ( $op_a1 and 1 of ($op_b*) )
      )
}
