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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "28143c7638f22342bff8edcd0bedd708e265948a5fcca750c302e2dca95ed9f0"
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "17a4bd9c95f2898add97f309fc6f9bcd"
      )
}

rule DragonFly_APT_Sep17_1 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
   strings:
      $s1 = "\\Update\\Temp\\ufiles.txt" fullword wide
      $s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
      $s3 = "*pass*.*" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule DragonFly_APT_Sep17_2 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
   strings:
      $s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" fullword wide
      $s2 = "C:\\Users\\Public\\Log.txt" fullword wide
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword wide
      $s4 = "***************** Mozilla Firefox ****************" fullword wide
      $s5 = "********************** Opera *********************" fullword wide
      $s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" fullword wide
      $s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" fullword wide
      $s8 = "**************** Internet Explorer ***************" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them )
}

rule DragonFly_APT_Sep17_3 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
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
