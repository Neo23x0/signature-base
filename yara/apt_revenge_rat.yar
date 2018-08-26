/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-04
   Identifier: RevengeRAT
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule RevengeRAT_Sep17 {
   meta:
      description = "Detects RevengeRAT malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-04"
      hash1 = "2a86a4b2dcf1657bcb2922e70fc787aa9b66ec1c26dc2119f669bd2ce3f2e94a"
      hash2 = "7c271484c11795876972aabeb277c7b3035f896c9e860a852d69737df6e14213"
      hash3 = "fe00c4f9c8439eea50b44f817f760d8107f81e2dba7f383009fde508ff4b8967"
   strings:
      $x1 = "Nuclear Explosion.g.resources" fullword ascii
      $x3 = "03C7F4E8FB359AEC0EEF0814B66A704FC43FB3A8" fullword ascii
      $x4 = "5B1EE7CAD3DFF220A95D1D6B91435D9E1520AC41" fullword ascii
      $x5 = "\\RevengeRAT\\" ascii
      $x6 = "Revenge-RAT client has been successfully installed." ascii
      $x7 = "Nuclear Explosion.exe" fullword ascii
      $x8 = " Revenge-RAT 201" wide

      $s1 = "{11111-22222-20001-00001}" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) ) or ( 3 of them )
}
