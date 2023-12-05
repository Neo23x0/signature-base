/*
   Yara Rule Set
   Copyright: Florian Roth
   Date: 2017-06-25
   Identifier: Rules that detect different malware characteristics
   Reference: Internal Research
   License: GPL
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 70
      date = "2017-07-17"
      modified = "2021-03-15"
      author = "Florian Roth (Nextron Systems)"
      nodeepdive = 1
      id = "d8a601d7-b99a-59dc-bfc7-bf0e35b5d8bd"
   strings:
      $x1 = "ReflectiveLoader" fullword ascii
      $x2 = "ReflectivLoader.dll" fullword ascii
      $x3 = "?ReflectiveLoader@@" ascii
      $x4 = "reflective_dll.x64.dll" fullword ascii
      $x5 = "reflective_dll.dll" fullword ascii

      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Panda Security, S.L." wide ascii
   condition:
      uint16(0) == 0x5a4d and (
            1 of ($x*) or
            pe.exports("ReflectiveLoader") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("?ReflectiveLoader@@YGKPAX@Z")
         )
      and not 1 of ($fp*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-20
   Identifier: Reflective DLL Loader
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Reflective_DLL_Loader_Aug17_1 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "f2f85855914345eec629e6fc5333cf325a620531d1441313292924a88564e320"
      id = "9a2674f8-5fdb-5a4d-a2b9-41e874939616"
   strings:
      $x1 = "\\Release\\reflective_dll.pdb" ascii
      $x2 = "reflective_dll.x64.dll" fullword ascii
      $s3 = "DLL Injection" fullword ascii
      $s4 = "?ReflectiveLoader@@YA_KPEAX@Z" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "4bf489ae7d1e6575f5bb81ae4d10862f" or
           pe.exports("?ReflectiveLoader@@YA_KPEAX@Z") or
           ( 1 of ($x*) or 2 of them )
        )
      ) or ( 2 of them )
}

rule DLL_Injector_Lynx {
   meta:
      description = "Detects Lynx DLL Injector"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
      id = "7a4c9949-c701-5ae2-a8b1-3ef0b08c1c04"
   strings:
      $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
      $x2 = "You've selected to inject into process: %s" fullword wide
      $x3 = "Lynx DLL Injector" fullword wide
      $x4 = "Reflective DLL Injector" fullword wide
      $x5 = "Failed write payload: %lu" fullword wide
      $x6 = "Failed to start payload: %lu" fullword wide
      $x7 = "Injecting payload..." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 800KB and
        1 of them
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_2 {
   meta:
      description = "Detects Reflective DLL Loader - suspicious - Possible FP could be program crack"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      score = 60
      hash1 = "c2a7a2d0b05ad42386a2bedb780205b7c0af76fe9ee3d47bbe217562f627fcae"
      hash2 = "b90831aaf8859e604283e5292158f08f100d4a2d4e1875ea1911750a6cb85fe0"
      id = "5948d9ba-e655-5b11-ad74-f650b3a753e7"
   strings:
      $x1 = "\\ReflectiveDLLInjection-master\\" ascii
      $s2 = "reflective_dll.dll" fullword ascii
      $s3 = "DLL injection" fullword ascii
      $s4 = "_ReflectiveLoader@4" ascii
      $s5 = "Reflective Dll Injection" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        (
           pe.imphash() == "59867122bcc8c959ad307ac2dd08af79" or
           pe.exports("_ReflectiveLoader@4") or
           2 of them
        )
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_3 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      modified = "2022-12-21"
      hash1 = "d10e4b3f1d00f4da391ac03872204dc6551d867684e0af2a4ef52055e771f474"
      id = "91842f58-5205-533d-9e97-a1e84fbf259d"
   strings:
      $s1 = "\\Release\\inject.pdb" ascii
      $s2 = "!!! Failed to gather information on system processes! " fullword ascii
      $s3 = "reflective_dll.dll" fullword ascii
      $s4 = "[-] %s. Error=%d" fullword ascii
      $s5 = "\\Start Menu\\Programs\\reflective_dll.dll" ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "26ba48d3e3b964f75ff148b6679b42ec" or
           2 of them
        )
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_4 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
      hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
      id = "d2a28ea6-a3f7-5ceb-86fd-1e5b7f916a41"
   strings:
      $x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii

      $s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
      $s2 = "<H2>Operating system: %s<H2>" fullword ascii
      $s3 = "<H2>System32 dir:  %s</H2>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and 2 of them
      )
}
