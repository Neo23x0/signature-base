/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-26
	Identifier: ProjectM
*/

/* Rule Set ----------------------------------------------------------------- */

rule ProjectM_DarkComet_1 {
	meta:
		description = "Detects ProjectM Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		modified = "2023-01-27"
		hash = "cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
		id = "6de74d73-f9b2-5e7f-b15e-f850425d849c"
	strings:
		$x1 = "DarkO\\_2" fullword ascii

		$a1 = "AVICAP32.DLL" fullword ascii
		$a2 = "IDispatch4" fullword ascii
		$a3 = "FLOOD/" fullword ascii
		$a4 = "T<-/HTTP://" ascii
		$a5 = "infoes" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them ) or ( all of them )
}

rule ProjectM_CrimsonDownloader {
	meta:
		description = "Detects ProjectM Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
		id = "2e0658c9-a93d-5eef-93a2-eb1ab29acaee"
	strings:
		$x1 = "E:\\Projects\\m_project\\main\\mj shoaib"

		$s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
		$s2 = "secure_scan.exe" fullword wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
		$s4 = "secure_scan|mswall" fullword wide
		$s5 = "[Microsoft-Security-Essentials]" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and $x1 ) or ( all of them )
}
