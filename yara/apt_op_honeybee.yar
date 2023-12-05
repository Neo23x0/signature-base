/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-03
   Identifier: Operation HoneyBee
   Reference: https://goo.gl/JAHZVL
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule HoneyBee_Dropper_MalDoc {
   meta:
      description = "Detects samples from Operation Honeybee"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
      hash1 = "86981680172bbf0865e7693fe5a2bbe9b3ba12b3f1a1536ef67915daab78004c"
      hash2 = "0d4352322160339f87be70c2f3fe096500cfcdc95a8dea975fdfc457bd347c44"
      id = "4e8dec29-2c0a-5760-91c9-88f67505a7f1"
   strings:
      $x1 = "cmd /c expand %TEMP%\\setup.cab -F:* %SystemRoot%\\System32"
      $x2 = "del /f /q %TEMP%\\setup.cab && cliconfg.exe"

      $s1 = "SELECT * FROM Win32_Processor" fullword ascii
      $s2 = "\"cmd /c `wusa " fullword ascii
      $s3 = "sTempPathP" fullword ascii
      $s4 = "sTempFile" fullword ascii
      $s5 = "GetObjectz" fullword ascii
      $s6 = "\\setup.cab" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 400KB and ( 1 of ($x*) or 4 of them )
}

rule OpHoneybee_Malware_1 {
   meta:
      description = "Detects malware from Operation Honeybee"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
      hash1 = "d31fe5cfa884e04ee26f323b8d104dcaa91146f5c7c216212fd3053afaade80f"
      hash2 = "fc2bcd38659ae83fd25b4f7091412ae9ba011612fa4dcc3ef665b2cae2a1d74f"
      hash3 = "2c5e5c86ca4fa172341c6bcbaa50984fb168d650ae9a33f2c6e6dccc1d57b369"
      hash4 = "439c305cd408dbb508e153caab29d17021a7430f1dbaec0c90ac750ba2136f5f"
      id = "5f48434e-efe6-5cd8-85e2-eabf528e6c58"
   strings:
      $x1 = "cmd /c taskkill /im cliconfg.exe /f /t && del /f /q" fullword ascii
      $x2 = "\\FTPCom_vs10\\Release\\Engine.pdb" ascii
      $x3 = "KXU/yP=B29tLzidqNRuf-SbVInw0oCrmWZk6OpFc7A5GTD1QxaJ3H8h4jMeEsYglv" fullword ascii
      $x4 = "D:\\Task\\MiMul\\" ascii

      $s1 = "[DLL_PROCESS_ATTACH]" fullword ascii
      $s2 = "cmd /c systeminfo >%s" fullword ascii
      $s3 = "post.txt" fullword ascii
      $s4 = "\\temp.ini" ascii
      $s5 = "[GetFTPAccountInfo_10001712]" fullword ascii
      $s6 = "ComSysAppMutex" fullword ascii
      $s7 = "From %s (%02d-%02d %02d-%02d-%02d).txt" fullword ascii
      $s8 = "%s %s %c%s%c" fullword ascii
      $s9 = "TO EVERYONE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
        pe.imphash() == "e14b59a79999cc0bc589a4cb5994692a" or
        pe.imphash() == "64400f452e2f60305c341e08f217b02c" or
        1 of ($x*) or
        3 of them
      )
}

rule OpHoneybee_MaoCheng_Dropper {
   meta:
      description = "Detects MaoCheng dropper from Operation Honeybee"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
      hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
      id = "b163e08e-3892-55f6-ae3e-30d2ba3f4310"
   strings:
      $x1 = "\\MaoCheng\\Release\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and 1 of them
}
