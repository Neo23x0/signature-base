
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-24
   Identifier: Armitage
   Reference: Internal Research

   This is a subset of the Armitage rule set included in THOR APT Scanner
*/

/* Rule Set ----------------------------------------------------------------- */

rule Armitage_msfconsole {
   meta:
      description = "Detects Armitage component"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
   strings:
      $s1 = "\\umeterpreter\\u >" fullword ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" fullword ascii
   condition:
      ( uint16(0) == 0x6d5e and
        filesize < 1KB and
        ( 8 of them )
      ) or ( all of them )
}

/* Removed 7 rules */

rule Armitage_MeterpreterSession_Strings {
   meta:
      description = "Detects Armitage component"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
      hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
   strings:
      $s1 = "session.meterpreter_read" fullword ascii
      $s2 = "sniffer_dump" fullword ascii
      $s3 = "keyscan_dump" fullword ascii
      $s4 = "mimikatz_command" fullword ascii
      $s5 = "MeterpreterSession.java" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}

rule Armitage_OSX {
   meta:
      description = "Detects Armitage component"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
      hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"
   strings:
      $x1 = "resources/covertvpn-injector.exe" fullword ascii
      $s10 = "resources/browserpivot.x64.dll" fullword ascii
      $s17 = "resources/msfrpcd_new.bat" fullword ascii
   condition:
      filesize < 6000KB and 1 of them
}
