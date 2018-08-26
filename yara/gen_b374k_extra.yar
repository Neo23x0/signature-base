/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-18
	Identifier: b374k - Back Connect Payload UPX
*/

rule b374k_back_connect {
	meta:
		description = "Detects privilege escalation tool"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Internal Analysis"
		date = "2016-08-18"
		score = 80
		hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"
	strings:
		$s1 = "AddAtomACreatePro" fullword ascii
		$s2 = "shutdow" fullword ascii
		$s3 = "/config/i386" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 10KB and all of them )
}
