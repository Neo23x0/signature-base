/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2018-10-21
   Identifier: Grey Energy
   Reference: https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/
   License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
*/

import "pe"

rule APT_GreyEnergy_Malware_Oct18_1 {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      hash1 = "6c52a5850a57bea43a0a52ff0e2d2179653b97ae5406e884aee63e1cf340f58b"
   strings:
      $x1 = "%SystemRoot%\\System32\\thinmon.dll" fullword ascii
      $s2 = "'Cannot delete list entry (fatal error)!9The module %s cannot be executed on this system (0x%.4x).%Enumerate all sessions on TSE" wide
      $s8 = "cbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbe" ascii
      $s14 = "configure the service" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      pe.imphash() == "98d1ad672d0db4b4abdcda73cc9835cb" and
      all of them
}

rule APT_GreyEnergy_Malware_Oct18_2 {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      hash1 = "c6a54912f77a39c8f909a66a940350dcd8474c7a1d0e215a878349f1b038c58a"
   strings:
      $s1 = "WioGLtonuaptWmrnttfepgetneemVsnygnV" fullword ascii
      $s2 = "PnSenariopoeKerGEtxrcy" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}

rule APT_GreyEnergy_Malware_Oct18_3 {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      hash1 = "0db5e5b68dc4b8089197de9c1e345056f45c006b7b487f7d8d57b49ae385bad0"
   strings:
      $x1 = "USQTUNPPQONOPOQUMSNUTRMRRLVPUOPMROPMPMQTPNPONVUOUQOMMNNSRSRQQVTPPRSSNVSTURTMMOPTONSQTOMONQVMQNUSONTQTUTSRRPVTONUQNORQMRRNRUSPS" fullword ascii
      $x2 = "tEMPiuP" fullword ascii
      $x3 = "sryCEMieye" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule APT_GreyEnergy_Malware_Oct18_4 {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      hash1 = "6974b8acf6a8f7684673b01753c3a8248a1c491900cccf771db744ca0442f96a"
      hash2 = "165a7853ef51e96ce3f88bb33f928925b24ca5336e49845fc5fc556812092740"
      hash3 = "4470e40f63443aa27187a36bbb0c2f4def42b589b61433630df842b6e365ae3d"
      hash4 = "c21cf6018c2ee0a90b9d2c401aae8071c90b5a4bc9848a94d678d77209464f79"
   strings:
      $x1 = "iiodttd.eWt" fullword ascii
      $x2 = "irnnaar-ite-ornaa-naa-asoeienaeaanlagoeas:acnuihaaa" fullword ascii
      $x3 = "NURVNTURVORSMSPPRTQMPTTQOQRP" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
         pe.imphash() == "279adfbd42308a07b3131ee57d067b3e" or
         1 of them
      )
}

rule APT_GreyEnergy_Malware_Oct18_5 {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      hash1 = "037723bdb9100d19bf15c5c21b649db5f3f61e421e76abe9db86105f1e75847b"
      hash2 = "b602ce32b7647705d68aedbaaf4485f1a68253f8f8132bd5d5f77284a6c2d8bb"
   strings:
      $s12 = "WespySSld.eQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}
