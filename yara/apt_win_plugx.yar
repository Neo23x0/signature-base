/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-08
	Identifier: PlugX Juni 2016
*/

/* Rule Set ----------------------------------------------------------------- */

rule PlugX_J16_Gen {
	meta:
		description = "Detects PlugX Malware samples from June 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research"
		date = "2016-06-08"
		id = "13ef1e80-7090-5a1e-bca7-8d3de0dc2247"
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
		$s14 = "\\bug.log" wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 4 of ($s*) ) ) or ( 8 of them )
}

rule PlugX_J16_Gen2 {
	meta:
		description = "Detects PlugX Malware Samples from June 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research"
		date = "2016-06-08"
		id = "28e9cbb9-cd60-555d-b033-4e2bf293adf2"
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
