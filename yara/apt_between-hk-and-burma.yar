rule dubseven_file_set
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for service files loading UP007"

	strings:
		$file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
		$file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
		$file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
		$file4 = "\\Microsoft\\Internet Explorer\\main.dll"
		$file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
		$file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
		$file7 = "\\Microsoft\\Internet Explorer\\mon"
		$file8 = "\\Microsoft\\Internet Explorer\\runas.exe"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		//Just a few of these as they differ
		3 of ($file*)
}

rule dubseven_dropper_registry_checks
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for registry keys checked for by the dropper"

	strings:
		$reg1 = "SOFTWARE\\360Safe\\Liveup"
		$reg2 = "Software\\360safe"
		$reg3 = "SOFTWARE\\kingsoft\\Antivirus"
		$reg4 = "SOFTWARE\\Avira\\Avira Destop"
		$reg5 = "SOFTWARE\\rising\\RAV"
		$reg6 = "SOFTWARE\\JiangMin"
		$reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for related dialog remnants. How rude."

	strings:
		$dia1 = "fuckMessageBox 1.0" wide
		$dia2 = "Rundll 1.0" wide

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		any of them
}


rule maindll_mutex
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Matches on the maindll mutex"

	strings:
		$mutex = "h31415927tttt"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		$mutex
}


rule SLServer_dialog_remains
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks / modified by Florian Roth"
		date = "2016/04/18"
		score = 75
		description = "Searches for related dialog remnants."

	strings:
		$slserver = "SLServer" wide fullword

		$fp1 = "Dell Inc." wide fullword
		$fp2 = "ScriptLogic Corporation" wide

		$extra1 = "SLSERVER" wide fullword
		$extra2 = "\\SLServer.pdb" ascii

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		// Reduce false positives
		not 1 of ($fp*) and
		1 of ($extra*) and

		$slserver
}

rule SLServer_mutex
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the mutex."

	strings:
		$mutex = "M&GX^DSF&DA@F"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		$mutex
}

rule SLServer_command_and_control
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the C2 server."

	strings:
		$c2 = "safetyssl.security-centers.com"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		$c2
}

rule SLServer_campaign_code
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the related campaign code."

	strings:
		$campaign = "wthkdoc0106"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		$campaign
}

rule SLServer_unknown_string
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for a unique string."

	strings:
		$string = "test-b7fa835a39"

	condition:
		//MZ header
		uint16(0) == 0x5A4D and

		//PE signature
		uint32(uint32(0x3C)) == 0x00004550 and

		$string
}
