/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-07-28
   Identifier: DarkHydrus
   Reference: https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_DarkHydrus_Jul18_1 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
      id = "fbd001c0-43c9-5429-84d6-7f62eadd8ff3"
   strings:
      $x1 = "Z:\\devcenter\\aggressor\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "d3666d1cde4790b22b44ec35976687fb" or
         1 of them
      )
}

rule APT_DarkHydrus_Jul18_2 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
      id = "1a21cbbf-f7e1-56eb-973b-35c1a811e210"
   strings:
      $s4 = "windir" fullword ascii /* Goodware String - occured 47 times */
      $s6 = "temp.dll" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "libgcj-12.dll" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "%s\\System32\\%s" fullword ascii /* Goodware String - occured 4 times */
      $s9 = "StartW" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule APT_DarkHydrus_Jul18_3 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"
      id = "1f766b49-3173-5f8a-ba52-a9ce9000be79"
   strings:
      $s2 = "Ws2_32.dll" fullword ascii
      $s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         pe.imphash() == "478eacfbe2b201dabe63be53f34148a5" or
         all of them
      )
}

rule HKTL_Unlicensed_CobaltStrike_EICAR_Jul18_5 {
   meta:
      description = "Detects strings found in CobaltStrike shellcode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      modified = "2021-06-17"
      hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"
      id = "d52536b8-dd6b-59be-8761-d22b6a279114"
   strings:
      $x1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
      $s2 = "libgcj-12.dll" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
         pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or
         all of ($s*) or
         $x1
      )
}

