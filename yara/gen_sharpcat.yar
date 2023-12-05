/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-10
	Identifier: SharpCat
*/

rule SharpCat {
	meta:
		description = "Detects command shell SharpCat - file SharpCat.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/SharpCat"
		date = "2016-06-10"
		hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"
		id = "94a7ce40-ac2f-598e-86c5-ee9fde1eeef0"
	strings:
		$x1 = "ShellZz" fullword ascii
		$s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s3 = "currentDirectory" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}
