/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-08
	Identifier: PlugX Juni 2016 MISP 3954
*/

/* Rule Set ----------------------------------------------------------------- */

rule PlugX_J16_Gen {
	meta:
		description = "Detects PlugX Malware samples from June 2016"
		author = "Florian Roth"
		reference = "MISP 3954"
		date = "2016-06-08"
		super_rule = 1
		hash1 = "00119101c6acdd8f4c5db4a9ac4772957aaf35958daf4a2ba6ad2b3719ab4f34"
		hash2 = "005afae5aa5beec765e74b461177dce8342067c29985ef9c683af7e2d92eeef0"
		hash3 = "0109d7a8d76993ca8af111ff6fcf96021c9250cd59717151fbd4bb3792bedc12"
		hash4 = "015616d0cba87cbec3ef7b200a6d278eb9d159ebe6865f82cc53faad30ec0fe9"
		hash5 = "017c1eabd3e2df34b9e73397cb06bd927462cfd4487e1adfd1efa13e3df9e1d0"
		hash6 = "1818ee0712108b86dbfd08b18dfa3e0d8e64cc6fc1f1cdd79990271cb3e4e8ba"
		hash7 = "5dff1e086c5191a0bd7ac13466b7a81a87e99e51968df2f32570eb031c537ab4"
		hash8 = "710326804b78ccd2782abc16354e389f0e36ba9474ebdced17337a13082ac12f"
		hash9 = "bf9a7f7b91d3ebe0eed2b2ddd661922784505e623be3e2cc142ffa639cd48c76"
		hash10 = "01f6ba7f3dd687fc27498c3187f5d60ff749ad10720049ab00859ae41b253040"
		hash11 = "da5adbd116520429a0ff401f6d5d6073e2864ba43f9a50dbbddd4a0a6a2730f1"
		hash12 = "0253f2c85f173508fafbac4b42beb7cf4639d4daab18ecac150613a7d806c05c"
		hash13 = "5a0fe1b2a4c60316d1a7a3a8b140283924d2d5a1f86c0ce173e85dd42cb8c160"
		hash14 = "392d43519b09adbb5b6336f00c60b5cc8b683b72b0c1558ef2b4dd3ba1a1ce25"
	strings:
		$x1 = "%WINDIR%\\SYSTEM32\\SERVICES.EXE" fullword wide
		$x2 = "\\\\.\\PIPE\\RUN_AS_USER(%d)" fullword wide
		$x3 = "LdrLoadShellcode" fullword ascii
		$x4 = "Protocol:[%4s], Host: [%s:%d], Proxy: [%d:%s:%d:%s:%s]" fullword ascii

		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" fullword wide
		$s2 = "%s\\msiexec.exe %d %d" fullword wide
		$s3 = "l%s\\sysprep\\CRYPTBASE.DLL" fullword wide
		$s4 = "%s\\msiexec.exe UAC" fullword wide
		$s5 = "CRYPTBASE.DLL" fullword wide
		$s6 = "%ALLUSERSPROFILE%\\SxS" fullword wide
		$s7 = "%s\\sysprep\\sysprep.exe" fullword wide
		$s8 = "\\\\.\\pipe\\a%d" fullword wide
		$s9 = "\\\\.\\pipe\\b%d" fullword wide
		$s10 = "EName:%s,EAddr:0x%p,ECode:0x%p,EAX:%p,EBX:%p,ECX:%p,EDX:%p,ESI:%p,EDI:%p,EBP:%p,ESP:%p,EIP:%p" fullword ascii
		$s11 = "Mozilla/4.0 (compatible; MSIE " fullword wide
		$s12 = "; Windows NT %d.%d" fullword wide
		$s13 = "SOFTWARE\\Microsoft\\Internet Explorer\\Version Vector" fullword wide
		$s14 = "\\bug.log" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 4 of ($s*) ) ) or ( 8 of them )
}

rule PlugX_J16_Gen2 {
	meta:
		description = "Detects PlugX Malware Samples from June 2016"
		author = "Florian Roth"
		reference = "MISP 3954"
		date = "2016-06-08"
		super_rule = 1
		hash1 = "5dff1e086c5191a0bd7ac13466b7a81a87e99e51968df2f32570eb031c537ab4"
		hash2 = "710326804b78ccd2782abc16354e389f0e36ba9474ebdced17337a13082ac12f"
	strings:
		$s1 = "XPlugKeyLogger.cpp" fullword ascii
		$s2 = "XPlugProcess.cpp" fullword ascii
		$s4 = "XPlgLoader.cpp" fullword ascii
		$s5 = "XPlugPortMap.cpp" fullword ascii
		$s8 = "XPlugShell.cpp" fullword ascii
		$s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
		$s12 = "XInstall.cpp" fullword ascii
		$s13 = "XPlugTelnet.cpp" fullword ascii
		$s14 = "XInstallUAC.cpp" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 2 of ($s*) ) ) or ( 5 of them )
}
