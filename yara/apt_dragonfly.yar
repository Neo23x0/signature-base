/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-12
   Identifier: DragonFly
   Reference: https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Unspecified_Malware_Sep1_A1 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "28143c7638f22342bff8edcd0bedd708e265948a5fcca750c302e2dca95ed9f0"
      id = "cff49e85-c8c3-5240-9948-0551e38e7040"
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "17a4bd9c95f2898add97f309fc6f9bcd"
      )
}

rule DragonFly_APT_Sep17_1 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
      id = "d219a54e-cb76-5c56-b64c-5019e811eeb1"
   strings:
      $s1 = "\\Update\\Temp\\ufiles.txt" wide
      $s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
      $s3 = "*pass*.*" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule DragonFly_APT_Sep17_2 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      modified = "2023-01-06"
      hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
      id = "e64f121d-a628-54b5-88f3-96eea388c155"
   strings:
      $s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" wide
      $s2 = "C:\\Users\\Public\\Log.txt" fullword wide
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword wide
      $s4 = "***************** Mozilla Firefox ****************" fullword wide
      $s5 = "********************** Opera *********************" fullword wide
      $s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" wide
      $s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" wide
      $s8 = "**************** Internet Explorer ***************" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them )
}

rule DragonFly_APT_Sep17_3 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
      id = "4eafd732-80bc-5f50-bf0d-096df4d35d61"
   strings:
      $s1 = "kernel64.dll" fullword ascii
      $s2 = "ws2_32.dQH" fullword ascii
      $s3 = "HGFEDCBADCBA" fullword ascii
      $s4 = "AWAVAUATWVSU" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and (
           pe.imphash() == "6f03fb864ff388bac8680ac5303584be" or
           all of them
        )
      )
}

rule DragonFly_APT_Sep17_4 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      id = "dbc0eebf-fc81-5a0b-b2e0-129d0b40b6f7"
   strings:
      $s1 = "screen.exe" fullword wide
      $s2 = "PlatformInvokeUSER32" fullword ascii
      $s3 = "GetDesktopImageF" fullword ascii
      $s4 = "PlatformInvokeGDI32" fullword ascii
      $s5 = "GetDesktopImage" fullword ascii
      $s6 = "Too many arguments, going to store in current dir" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}
