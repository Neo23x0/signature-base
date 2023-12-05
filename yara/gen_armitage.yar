
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
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-24"
      modified = "2022-08-18"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
      id = "9c610cd0-663e-54ea-a0f2-6c044fc45d23"
   strings:
      $s1 = "\\umeterpreter\\u >" ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" ascii
   condition:
      filesize < 1KB and 2 of them
}

/* Removed 7 rules */

rule Armitage_MeterpreterSession_Strings {
   meta:
      description = "Detects Armitage component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
      hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
      id = "c49fdb73-1c95-5c63-b039-2fddb77290dc"
   strings:
      $s1 = "session.meterpreter_read" fullword ascii
      $s2 = "sniffer_dump" fullword ascii
      $s3 = "keyscan_dump" fullword ascii
      $s4 = "MeterpreterSession.java" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}

rule Armitage_OSX {
   meta:
      description = "Detects Armitage component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
      hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"
      id = "e886e866-c163-56fb-9631-c586e9f23f9e"
   strings:
      $x1 = "resources/covertvpn-injector.exe" fullword ascii
      $s10 = "resources/browserpivot.x64.dll" fullword ascii
      $s17 = "resources/msfrpcd_new.bat" fullword ascii
   condition:
      filesize < 6000KB and 1 of them
}
