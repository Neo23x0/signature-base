/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-08
	Identifier: Suckfly Nidiran
*/

/* Rule Set ----------------------------------------------------------------- */

rule Nidiran_Trojan_1 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "47731c9d985ebc2bd7227fced3cc44c6d72e29b52f76fccbdaddd76cc3450706"
		hash2 = "c2022e1114b162e79e44d974fd310d53e1bbdd8cb4f217553c1227cafed78855"
	strings:
		$x1 = "RUN SHELLCODE FAIL" fullword ascii
		$x2 = "RUN DLLMEM THREAD FAIL" fullword ascii

		$s1 = "cmd.exe /c %s" fullword ascii
		$s2 = "CreateProcess returned %d, error at %d" fullword ascii
		$s3 = "RUN PROCESS FAILD!" fullword ascii
		$s5 = "RUN PROCESS SUCC!" fullword ascii
		$s6 = "error to create pipe!" fullword ascii
		$s7 = "5308.tmp" fullword ascii
		$s8 = "MODIFYCONFIG FAIL!" fullword ascii
		$s9 = "%s\\%08x.exe" fullword ascii
		$s10 = "GetFileAttributes FILE FAILD" fullword ascii
		$s11 = "DOWNLOAD FILE FAILD" fullword ascii
		$s12 = "MODIFYCONFIG SUCC!" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 10 of them )
}

rule Nidiran_Trojan_2 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "eaee2bf83cf90d35dab8a4711f7a5f2ebf9741007668f3746995f4564046fbdf"
	strings:
		$s1 = "%userprofile%\\Security Center\\secriter.dll" fullword ascii
		$s2 = "WorkDll.dll" fullword ascii
		$s3 = "InstallUserProcess is called" fullword ascii
		$s4 = "DLL_PROCESS_ATTACH is called" fullword ascii
		$s5 = "CreateRemoteThread Succ" fullword ascii
		$s6 = "DoRunRemote" fullword ascii
		$s7 = "DllRegisterServer is called" fullword ascii
		$s8 = "DoInstallEntry is called" fullword ascii
		$s9 = "copy Fail" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 5 of ($s*) ) or ( all of them )
}

rule Nidiran_Trojan_3 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
	strings:
		$s1 = "WriteProcessMemory fail at %d " fullword ascii
		$s2 = "CreateRemoteThread fail at %d " fullword ascii
		$s3 = "VirtualAllocEx fail at %d " fullword ascii
		$s4 = "CreateRemoteThread Succ" fullword ascii
		$s5 = "VirtualAllocEx succ" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 3 of ($s*) ) or ( all of them )
}
