/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-04
	Identifier: Terracotta APT
	Comment: Reduced Rule Set
*/

/* Rule Set ----------------------------------------------------------------- */

rule Apolmy_Privesc_Trojan {
	meta:
		description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 80
		hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
	strings:
		$s1 = "[%d] Failed, %08X" fullword ascii
		$s2 = "[%d] Offset can not fetched." fullword ascii
		$s3 = "PowerShadow2011" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Mithozhan_Trojan {
	meta:
		description = "Mitozhan Trojan used in APT Terracotta"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"
	strings:
		$s1 = "adbrowser" fullword wide 
		$s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
		$s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule RemoteExec_Tool {
	meta:
		description = "Remote Access Tool used in APT Terracotta"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"
	strings:
		$s0 = "cmd.exe /q /c \"%s\"" fullword ascii 
		$s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii 
		$s2 = "This is a service executable! Couldn't start directly." fullword ascii 
		$s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii 
		$s4 = "TermHlp_stdout" fullword ascii 
		$s5 = "TermHlp_stdin" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 75KB and 4 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule LiuDoor_Malware_1 {
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "deed6e2a31349253143d4069613905e1dfc3ad4589f6987388de13e33ac187fc"
		hash2 = "4575e7fc8f156d1d499aab5064a4832953cd43795574b4c7b9165cdc92993ce5"
		hash3 = "ad1a507709c75fe93708ce9ca1227c5fefa812997ed9104ff9adfec62a3ec2bb"
	strings:
		$s1 = "svchostdllserver.dll" fullword ascii 
		$s2 = "SvcHostDLL: RegisterServiceCtrlHandler %S failed" fullword ascii 
		$s3 = "\\nbtstat.exe" fullword ascii
		$s4 = "DataVersionEx" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule LiuDoor_Malware_2 {
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "f3fb68b21490ded2ae7327271d3412fbbf9d705c8003a195a705c47c98b43800"
		hash2 = "e42b8385e1aecd89a94a740a2c7cd5ef157b091fabd52cd6f86e47534ca2863e"
	strings:
		$s0 = "svchostdllserver.dll" fullword ascii 
		$s1 = "Lpykh~mzCCRv|mplpykCCHvq{phlCC\\jmmzqkIzmlvpqCC" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}
