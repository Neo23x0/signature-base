import "pe"

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-24
   Identifier: Kasper
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule KasperMalware_Oct17_1 {
   meta:
      description = "Detects Kasper Backdoor"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-10-24"
      hash1 = "758bdaf26a0bd309a5458cb4569fe1c789cf5db087880d6d1676dec051c3a28d"
   strings:
      $x1 = "\\Release\\kasper.pdb" ascii
      $x2 = "C:\\D@oc@um@en@ts a@nd Set@tings\\Al@l Users" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and (
         pe.imphash() == "2bceb64cf37acd34bc33b38f2cddfb61" or
         1 of them
      )
}
