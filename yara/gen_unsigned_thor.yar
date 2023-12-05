
import "pe"

rule SUSP_THOR_Unsigned_Oct23_1 {
   meta:
      description = "Detects unsigned version of THOR scanner, which could be a backdoored / modified version of the scanner"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2023-10-28"
      score = 75
      id = "2ca6a192-675e-5f02-a7b1-40369eeb9904"
   strings:
      $s1 = "THOR APT Scanner" wide fullword
      $s2 = "Nextron Systems GmbH" wide fullword

      /* OriginalFilename\x00thor */
      $sc1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 68 00 6F 00 72 } 
   condition:
      uint16(0) == 0x5a4d
      and all of them
      and pe.number_of_signatures == 0
}
