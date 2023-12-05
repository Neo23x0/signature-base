/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-08
   Identifier: Rehashed RAT
   Reference: https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Rehashed_RAT_1 {
   meta:
      description = "Detects malware from Rehashed RAT incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
      date = "2017-09-08"
      hash1 = "37bd97779e854ea2fc43486ddb831a5acfd19cf89f06823c9fd3b20134cb1c35"
      id = "24536421-3f8f-58f3-8245-06c519d7a21a"
   strings:
      $x1 = "C:\\Users\\hoogle168\\Desktop\\"
      $x2 = "\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii

      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s2 = "NewCoreCtrl08.dll" fullword ascii
      $s3 = "GET /%s%s%s%s HTTP/1.1" fullword ascii
      $s4 = "http://%s:%d/%s%s%s%s" fullword ascii
      $s5 = "MyTmpFile.Dat" fullword wide
      $s6 = "root\\%s" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and (
            pe.imphash() == "893212784d01f11aed9ebb42ad2561fc" or
            pe.exports("ProcessTrans") or
            ( 1 of ($x*) or 4 of them )
         )
      ) or ( all of them )
}

rule Rehashed_RAT_2 {
   meta:
      description = "Detects malware from Rehashed RAT incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
      date = "2017-09-08"
      hash1 = "49efab1dedc6fffe5a8f980688a5ebefce1be3d0d180d5dd035f02ce396c9966"
      id = "fcf82155-10da-56b7-879b-841c4ae5023b"
   strings:
      $x1 = "dalat.dulichovietnam.net" fullword ascii
      $x2 = "web.Thoitietvietnam.org" fullword ascii

      $a1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64)" fullword ascii
      $a2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii

      $s1 = "GET /%s%s%s%s HTTP/1.1" fullword ascii
      $s2 = "http://%s:%d/%s%s%s%s" fullword ascii
      $s3 = "{521338B8-3378-58F7-AFB9-E7D35E683BF8}" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and (
           pe.imphash() == "9c4c648f4a758cbbfe28c8850d82f931" or
           ( 1 of ($x*) or 3 of them )
        )
      ) or ( 4 of them )
}

rule Rehashed_RAT_3 {
   meta:
      description = "Detects malware from Rehashed RAT incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
      date = "2017-09-08"
      modified = "2022-12-21"
      hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"
      id = "59871be1-295f-54ee-ab4d-4f9e5fdc2935"
   strings:
      $x1 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii
      $s2 = "psisrndrx.ebd" fullword wide
      $s3 = "pbad exception" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 2 of them )
}
