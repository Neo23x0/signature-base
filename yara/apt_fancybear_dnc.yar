/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-14
	Identifier: Fancy Bear and Cozy Bear Report - CrowdStrike
*/

/* Rule Set ----------------------------------------------------------------- */

rule COZY_FANCY_BEAR_Hunt {
	meta:
		description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
		id = "e81b4368-7383-5a48-a89a-f91b9306326e"
	strings:
		$s1 = "185.100.84.134" ascii wide fullword
		$s2 = "58.49.58.58" ascii wide fullword
		$s3 = "218.1.98.203" ascii wide fullword
		$s4 = "187.33.33.8" ascii wide fullword
		$s5 = "185.86.148.227" ascii wide fullword
		$s6 = "45.32.129.185" ascii wide fullword
		$s7 = "23.227.196.217" ascii wide fullword
	condition:
		uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt {
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
		id = "3c5c8843-81ba-510c-82ed-4b6e2286bdb2"
	strings:
		$s1 = "pagemgr.exe" wide fullword
	condition:
		uint16(0) == 0x5a4d and 1 of them
}
