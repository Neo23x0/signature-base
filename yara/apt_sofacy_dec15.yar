/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-04
	Identifier: Sofacy Malware
*/

rule Sofacy_Malware_StrangeSpaces {
	meta:
		description = "Detetcs strange strings from Sofacy malware with many spaces"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
	strings:
		$s2 = "Delete Temp Folder Service                                  " fullword wide
		$s3 = " Operating System                        " fullword wide
		$s4 = "Microsoft Corporation                                       " fullword wide
		$s5 = " Microsoft Corporation. All rights reserved.               " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and 3 of them
}

rule Sofacy_Malware_AZZY_Backdoor_1 {
	meta:
		description = "AZZY Backdoor - Sample 1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"
	strings:
		$s0 = "advstorshell.dll" fullword wide
		$s1 = "advshellstore.dll" fullword ascii
		$s2 = "Windows Advanced Storage Shell Extension DLL" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_Implant_1 {
	meta:
		description = "AZZY Backdoor Implant 4.3 - Sample 1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
	strings:
		$s1 = "\\tf394kv.dll" fullword wide
		$s2 = "DWN_DLL_MAIN.dll" fullword ascii
		$s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
		$s4 = "?Applicate@@YGHXZ" ascii
		$s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_HelperDLL {
	meta:
		description = "Dropped C&C helper DLL for AZZY 4.3"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"
	strings:
		$s0 = "snd.dll" fullword ascii
		$s1 = "InternetExchange" fullword ascii
		$s2 = "SendData"
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

/* Super Rules ------------------------------------------------------------- */

rule Sofacy_CollectorStealer_Gen1 {
	meta:
		description = "Generic rule to detect Sofacy Malware Collector Stealer"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		super_rule = 1
		hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
	strings:
		$s0 = "NvCpld.dll" fullword ascii
		$s1 = "NvStop" fullword ascii
		$s2 = "NvStart" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Sofacy_CollectorStealer_Gen2 {
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"
	strings:
		$s1 = "msdetltemp.dll" fullword ascii
		$s2 = "msdeltemp.dll" fullword wide
		$s3 = "Delete Temp Folder Service" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Sofacy_CollectorStealer_Gen3 {
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
	strings:
		$s1 = "NvCpld.dll" fullword ascii
		$s4 = "NvStart" fullword ascii
		$s5 = "NvStop" fullword ascii

		$a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
		$a2 = "IGFSRVC.dll" fullword wide
		$a3 = "Common User Interface" fullword wide
		$a4 = "igfsrvc Module" fullword wide

		$b1 = " Operating System                        " fullword wide
		$b2 = "Microsoft Corporation                                       " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and
		( all of ($s*) and (all of ($a*) or all of ($b*)))
}
