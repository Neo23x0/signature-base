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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"
   strings:
      $s2 = "Ws2_32.dll" fullword ascii
      $s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         pe.imphash() == "478eacfbe2b201dabe63be53f34148a5" or
         all of them
      )
}

rule APT_DarkHydrus_Jul18_4 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
      hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
   strings:
      $s1 = "Error #bdembed1 -- Quiting" fullword ascii
      $s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $s3 = "\\a.txt" fullword ascii
      $s4 = "command.com" fullword ascii /* Goodware String - occured 91 times */
      $s6 = "DFDHERGDCV" fullword ascii
      $s7 = "DFDHERGGZV" fullword ascii
      $s8 = "%s%s%s%s%s%s%s%s" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 5 of them
}

rule APT_DarkHydrus_Jul18_5 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
      $s2 = "libgcj-12.dll" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
         pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or
         all of them
      )
}
