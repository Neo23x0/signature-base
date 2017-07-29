/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-27
   Identifier: PowerShell Empire Eval
   2 of 8 rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_Emp_Eval_Jul17_A1 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27"
      hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
   strings:
      $s1 = "powershell" wide
      $s2 = "pshcmd" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule PowerShell_Emp_Eval_Jul17_A2 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27"
      hash1 = "e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51"
   strings:
      $x1 = "\\support\\Release\\ab.pdb" ascii
      $s2 = "powershell.exe" ascii fullword
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}