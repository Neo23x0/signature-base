/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-31
   Identifier: KHRAT RAT
   Reference: https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule KHRAT_Malware {
   meta:
      description = "Detects an Imphash of KHRAT malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31"
      hash1 = "53e27fd13f26462a58fa5587ecd244cab4da23aa80cf0ed6eb5ee9f9de2688c1"
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "6a8478ad861f98f8428a042f74de1944"
}
