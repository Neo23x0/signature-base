/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-19
	Identifier: Invoke-Mimikatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_Mimikatz {
	meta:
		description = "Detects Invoke-Mimikatz String"
		author = "Florian Roth"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		date = "2016-08-03"
	strings:
		$x1 = "Invoke-Mimikatz" wide fullword
	condition:
      1 of them
}
