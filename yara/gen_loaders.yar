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

rule Winnti_Malware_N_EAnalysis {
   meta:
      description = "Detects a unspecified hack tool or malware using a reflective loader"
      reference = "Internal Research"
      score = 60
   condition:
      uint16(0) == 0x5a4d and (
            pe.exports("ReflectiveLoader")
         )
}
