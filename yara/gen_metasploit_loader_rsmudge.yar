/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-04-20
	Identifier: Metasploit Loader
*/

/* Rule Set ----------------------------------------------------------------- */

rule Metasploit_Loader_RSMudge {
	meta:
		description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/rsmudge/metasploit-loader"
		date = "2016-04-20"
		hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"
		id = "4d8a215e-a942-5df9-bdad-0c4158992429"
	strings:
		$s1 = "Could not resolve target" fullword ascii
		$s2 = "Could not connect to target" fullword ascii
		$s3 = "%s [host] [port]" fullword ascii
		$s4 = "ws2_32.dll is out of date." fullword ascii
		$s5 = "read a strange or incomplete length value" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and ( 3 of ($s*) ) ) or ( all of them )
}
