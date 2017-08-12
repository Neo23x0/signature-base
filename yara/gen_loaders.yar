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
      score = 60
   strings:
      $s1 = "ReflectiveLoader" fullword ascii
      $s2 = "?ReflectiveLoader@@" ascii
   condition:
      uint16(0) == 0x5a4d and (
            1 of them or
            pe.exports("ReflectiveLoader") or
            pe.exports("_ReflectiveLoader@4")
         )
}
