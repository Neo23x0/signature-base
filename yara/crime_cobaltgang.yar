/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-09
   Identifier: Cobalt Gang
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

/* Removed Beacon rules - only in THOR */

rule CobaltStrike_CN_Group_BeaconDropper_Aug17 {
   meta:
      description = "Detects Script Dropper of Cobalt Gang used in August 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-09"
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
      hash2 = "1c845bb0f6b9a96404af97dcafdc77f1629246e840c01dd9f1580a341f554926"
      hash3 = "6206e372870ea4f363be53557477f9748f1896831a0cdef3b8450a7fb65b86e1"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
      date = "2017-08-09"
      hash1 = "6d70673b723f338b3febc9f1d69463bdd4775539cb92b5a5d8fccc0d977fa2f0"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
      date = "2017-08-09"
      hash1 = "80791d5e76782cc3cd14f37f351e33b860818784192ab5b650f1cdf4f131cf72"
   strings:
      $s1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}
