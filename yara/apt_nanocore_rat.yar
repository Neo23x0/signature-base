/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-04-22
   Identifier: Nanocore RAT
*/

rule Nanocore_RAT_Gen_1 {
   meta:
      description = "Detetcs the Nanocore RAT and similar malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      score = 70
      hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
      id = "b007e0ce-e64f-5027-95ff-d178383e3b59"
   strings:
      $x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
      $x2 = "RunPE1" fullword ascii
      $x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
      $x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
      $x5 = "Monitorinjection" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Gen_2 {
   meta:
      description = "Detetcs the Nanocore RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 100
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"
      id = "74124961-3b0e-5808-b495-90437d3a5999"
   strings:
      $x1 = "NanoCore.ClientPluginHost" fullword ascii
      $x2 = "IClientNetworkHost" fullword ascii
      $x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}

rule Nanocore_RAT_Sample_1 {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 75
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"
      id = "381d3caf-77de-544c-869c-4d9f0cae148f"
   strings:
      $x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
      $x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
      $x3 = "popthatkitty.Resources.resources" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule Nanocore_RAT_Sample_2 {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 75
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
      id = "81f6771a-29a3-5fa0-8d24-ea717d3c5251"
   strings:
      $s1 = "U4tSOtmpM" fullword ascii
      $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" wide
      $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-19
   Identifier: NanoCore RAT
   Reference: Internal Research - T2T
*/

/* Rule Set ----------------------------------------------------------------- */

rule Nanocore_RAT_Feb18_1 {
   meta:
      description = "Detects Nanocore RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - T2T"
      date = "2018-02-19"
      hash1 = "aa486173e9d594729dbb5626748ce10a75ee966481b68c1b4f6323c827d9658c"
      id = "6db0c8a7-8c31-58a6-8732-de6663fec16b"
   strings:
      $x1 = "NanoCore Client.exe" fullword ascii
      $x2 = "NanoCore.ClientPluginHost" fullword ascii

      $s1 = "PluginCommand" fullword ascii
      $s2 = "FileCommand" fullword ascii
      $s3 = "PipeExists" fullword ascii
      $s4 = "PipeCreated" fullword ascii
      $s5 = "IClientLoggingHost" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
        1 of ($x*) or
        5 of them
      )
}

rule Nanocore_RAT_Feb18_2 {
   meta:
      description = "Detects Nanocore RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - T2T"
      date = "2018-02-19"
      hash1 = "377ef8febfd8df1a57a7966043ff0c7b8f3973c2cf666136e6c04080bbf9881a"
      id = "83a8ad4d-0bef-5ba2-aa10-eac5601f2c7b"
   strings:
      $s1 = "ResManagerRunnable" fullword ascii
      $s2 = "TransformRunnable" fullword ascii
      $s3 = "MethodInfoRunnable" fullword ascii
      $s4 = "ResRunnable" fullword ascii
      $s5 = "RunRunnable" fullword ascii
      $s6 = "AsmRunnable" fullword ascii
      $s7 = "ReadRunnable" fullword ascii
      $s8 = "ExitRunnable" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}
