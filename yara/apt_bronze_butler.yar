/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-14
   Identifier: Bronze Butler
   Reference: https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule BronzeButler_Daserf_Delphi_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "89a80ca92600af64eb9c32cab4e936c7d675cf815424d72438973e2d6788ef64"
      hash2 = "b1bd03cd12638f44d9ace271f65645e7f9b707f86e9bcf790e0e5a96b755556b"
      hash3 = "22e1965154bdb91dd281f0e86c8be96bf1f9a1e5fe93c60a1d30b79c0c0f0d43"
      id = "88372e62-3bba-58dc-825c-f35533e42825"
   strings:
      $s1 = "Services.exe" fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii
      $s3 = "l32.dll" fullword ascii
      $s4 = "tProcess:" fullword ascii
      $s5 = " InjectPr" ascii
      $s6 = "Write$Error creating variant or safe array\x1fInvalid argument to time encode" fullword wide
      $s7 = "on\\run /v " fullword ascii
      $s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" fullword ascii
      $s9 = "ms1ng2d3d2.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule BronzeButler_Daserf_C_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "a4afd9df1b4cc014c3a89d7b4a560fa3e368b02286c42841762714b23e68cc05"
      hash2 = "90ac1fb148ded4f46949a5fea4cd8c65d4ea9585046d66459328a5866f8198b2"
      hash3 = "331ac0965b50958db49b7794cc819b2945d7b5e5e919c185d83e997e205f107b"
      hash4 = "b1fdc6dc330e78a66757b77cc67a0e9931b777cd7af9f839911eecb74c04420a"
      hash5 = "15abe7b1355cd35375de6dde57608f6d3481755fdc9e71d2bfc7c7288db4cd92"
      hash6 = "85544d2bcaf8e6ca32bbc0a9e9583c9db1dce837043f555a7ff66363d5858439"
      hash7 = "2dc24622c1e91642a21a64c0dd31cbe953e8f77bd3d6abcf2c4676c3b11bb162"
      hash8 = "2bdb88fa24cffba240b60416835189c76a9920b6c3f6e09c3c4b171c2f57031c"
      id = "62a5cc4a-7c58-5e4d-ac23-8d1f850a540a"
   strings:
      $s1 = "(c) 2010 DYAMAR EnGineerinG, All rights reserved, http://www.dyamar.com." fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)" fullword ascii

      $a1 = "ndkkwqgcm" fullword ascii
      $a2 = "RtlGetCo" fullword ascii
      $a3 = "hutils" fullword ascii

      $b1 = "%USERPROFILE%\\System" fullword ascii
      $b2 = "msid.dat" fullword ascii
      $b3 = "DRIVE_REMOTE" fullword wide
      $b4 = "%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $b5 = "jcbhe.asp" fullword ascii
      $b6 = "edset.asp" fullword ascii
      $b7 = "bxcve.asp" fullword ascii
      $b8 = "hcvery.php" fullword ascii
      $b9 = "ynhkef.php" fullword ascii
      $b10 = "dkgwey.php" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
         pe.imphash() == "088382f4887e3b2c4bd5157f2d72b618" or
         all of ($a*) or
         4 of them
      )
}

rule BronzeButler_DGet_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"
      id = "d60fcc9f-0f17-5871-9e8e-71d26e2f46bc"
   strings:
      $s2 = "DGet Tool Made by XZ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule BronzeButler_UACBypass_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"
      id = "01853352-58fc-56a3-8c20-08405c71e251"
   strings:
      $x1 = "\\Release\\BypassUacDll.pdb" ascii
      $x2 = "%programfiles%internet exploreriexplore.exe" fullword wide
      $x3 = "Elevation:Administrator!new:{3ad055" fullword wide
      $x4 = "BypassUac.pdb" fullword ascii
      $x5 = "[bypassUAC] started X64" fullword wide
      $x6 = "[bypassUAC] started X86" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them )
}

rule BronzeButler_xxmm_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "7197de18bc5a4c854334ff979f3e4dafa16f43d7bf91edfe46f03e6cc88f7b73"
      id = "0e413e3a-fb61-58bc-9ecb-4ef76e83a7f3"
   strings:
      $x1 = "\\Release\\ReflectivLoader.pdb" ascii
      $x3 = "\\Projects\\xxmm2\\Release\\" ascii
      $x5 = "http://127.0.0.1/phptunnel.php" fullword ascii

      $s1 = "xxmm2.exe" fullword ascii
      $s2 = "\\AvUpdate.exe" wide
      $s3 = "stdapi_fs_file_download" fullword ascii
      $s4 = "stdapi_syncshell_open" fullword ascii
      $s5 = "stdapi_execute_sleep" fullword ascii
      $s6 = "stdapi_syncshell_kill" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and (
         1 of ($x*) or
         4 of them
      )
}

rule BronzeButler_RarStar_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "0fc1b4fdf0dc5373f98de8817da9380479606f775f5aa0b9b0e1a78d4b49e5f4"
      id = "770270b3-6743-5efb-84d8-b63f1df800d9"
   strings:
      $s1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.0;+SV1)" fullword wide
      $s2 = "http://www.google.co.jp" fullword wide
      $s3 = "16D73E22-873D-D58E-4F42-E6055BC9825E" fullword ascii
      $s4 = "\\*.rar" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-08
   Identifier: Bronze Butler
   Reference: https://goo.gl/ffeCfd
*/

/* Rule Set ----------------------------------------------------------------- */

rule Daserf_Nov1_BronzeButler {
   meta:
      description = "Detects Daserf malware used by Bronze Butler"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/ffeCfd"
      date = "2017-11-08"
      hash1 = "5ede6f93f26ccd6de2f93c9bd0f834279df5f5cfe3457915fae24a3aec46961b"
      id = "58c4d3dc-c516-567b-8746-4e185c3cd328"
   strings:
      $x1 = "mstmp1845234.exe" fullword ascii
      /* Bronce Butler UA String - see google search */
      $x2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)" fullword ascii
      $x3 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii

      $s1 = "Content-Type: */*" fullword ascii
      $s2 = "ProxyEnable" ascii fullword
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii fullword
      $s4 = "iexplore.exe" ascii fullword
      /* Looks random but present in many samples */
      $s5 = "\\SOFTWARE\\Microsoft\\Windows\\Cu" ascii
      $s6 = "rrentVersion\\Internet Settings" fullword ascii
      $s7 = "ws\\CurrentVersion\\Inter" fullword ascii
      $s8 = "Documents an" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 5 of them )
}

