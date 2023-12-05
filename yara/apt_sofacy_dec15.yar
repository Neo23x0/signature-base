/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-04
	Identifier: Sofacy Malware
*/

rule Sofacy_Malware_StrangeSpaces {
	meta:
		description = "Detetcs strange strings from Sofacy malware with many spaces"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		id = "60f99b88-f256-5289-852c-c0bf27f1cbd4"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"
		id = "184dc45e-8014-5dcf-a033-d77586c60fdf"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
		id = "ec6bf8ca-ccb9-532e-8b0d-1fba59efa2da"
	strings:
		$s1 = "\\tf394kv.dll" wide
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"
		id = "eae089a0-21dc-5d6e-a4bc-7181dc9b8b35"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		super_rule = 1
		hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		id = "f9462dd9-f6b6-59f4-a443-12d6f3be444e"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"
		id = "03ced94f-de20-56c5-bf17-1ec7d8610684"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		id = "d2ee1a22-6aae-51fc-9043-a7ba99769376"
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
