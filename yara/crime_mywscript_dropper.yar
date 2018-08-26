/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-27
   Identifier: MyWScript
*/

/* Rule Set ----------------------------------------------------------------- */

rule MyWScript_CompiledScript {
   meta:
      description = "Detects a scripte with default name Mywscript compiled with Script2Exe (can also be a McAfee tool https://community.mcafee.com/docs/DOC-4124)"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-27"
      score = 65
      hash1 = "515f5188ba6d039b8c38f60d3d868fa9c9726e144f593066490c7c97bf5090c8"
   strings:
      $x1 = "C:\\Projets\\vbsedit_source\\script2exe\\Release\\mywscript.pdb" fullword ascii
      $s1 = "mywscript2" fullword wide
      $s2 = "MYWSCRIPT2" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and ( $x1 or 2 of them )
}
