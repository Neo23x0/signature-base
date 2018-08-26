/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-23
	Identifier: Ghost Dragon Gh0st RAT
*/

rule GhostDragon_Gh0stRAT {
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "f9a669d22866cd041e2d520c5eb093188962bea8864fdfd0c0abb2b254e9f197"
		hash2 = "99ee5b764a5db1cb6b8a4f62605b5536487d9c35a28a23de8f9174659f65bcb2"
		hash3 = "6c7f8ba75889e0021c4616fcbee86ac06cd7f5e1e355e0cbfbbb5110c08bb6df"
		hash4 = "b803381535ac24ce7c8fdcf6155566d208dfca63fd66ec71bbc6754233e251f5"
	strings:
		$x1 = "REG ADD HKEY_LOCAL_MACHINE\\%s /v ServiceDll /t REG_EXPAND_SZ /d \"%s\"" fullword ascii
		$x2 = "Global\\REALCHEL_GLOBAL_SUBMIT_20031020_" fullword ascii
		$x3 = "\\xclolg2.tmp" fullword ascii
		$x4 = "Http/1.1 403 Forbidden" fullword ascii
		$x5 = "%sxsd%d.pif" fullword ascii
		$x6 = "%s\\%s32.dl_" fullword ascii
		$x7 = "%-23s %-16s  0x%x(%02d)" fullword ascii
		$x8 = "RegSetValueEx(start)" fullword ascii
		$x9 = "%s\\%s64.dl_" fullword ascii
		$x10 = "$#REGMASTERKEY$WebCat was successfully started" fullword wide

		$s1 = "viewsc.dll" fullword ascii
		$s2 = "Proxy-Connection:   Keep-Alive" fullword ascii
		$s3 = "\\sfc_os.dll" fullword ascii
		$s4 = "Mozilla/4.0 (compatible)" fullword ascii
		$s5 = "Http/1.1 403 Forbidden" fullword ascii
		$s6 = "CONNECT   %s:%d   HTTP/1.1" fullword ascii
		$s7 = "WindowsUpperVersion" fullword ascii
		$s8 = "[%d-%d-%d %d:%d:%d] (%s)" fullword ascii
		$s9 = "SOFTWARE\\Microsoft\\DataAccess\\%s" fullword ascii
		$s10 = "%s sp%d(%d)" fullword ascii
		$s11 = "OpenSC ERROR " fullword ascii
		$s12 = "get rgspath error " fullword ascii
		$s13 = "Global\\GLOBAL_SUBMIT_0234_" fullword ascii
		$s14 = "Global\\_vc_ck_ %d" fullword ascii
	condition:
		(
			uint16(0) == 0x5a4d and filesize < 500KB
			and (
				1 of ($x*) or 4 of ($s*)
			)
		) or ( 6 of them )
}

rule GhostDragon_Gh0stRAT_Sample2 {
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "71a52058f6b5cef66302c19169f67cf304507b4454cca83e2c36151da8da1d97"
	strings:
		$x1 = "AdobeWpk" fullword ascii
		$x2 = "seekin.dll" fullword ascii

		$c1 = "Windows NT 6.1; Trident/6.0)" fullword ascii
		$c2 = "Mozilla/5.0 (compatible; MSIE 10.0; " fullword ascii
	condition:
		(
			uint16(0) == 0x5a4d and filesize < 80KB and (
				all of ($x*) or all of ($c*)
			)
		) or ( all of them )
}

rule GhostDragon_Gh0stRAT_Sample3 {
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"
	strings:
		$op1 = { 44 24 15 65 88 54 24 16 c6 44 24 }
		$op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e }
		$op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 }
	condition:
		all of them
}
