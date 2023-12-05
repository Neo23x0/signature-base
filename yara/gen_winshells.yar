/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-26
	Identifier: Windows Shells
*/

/* Rule Set ----------------------------------------------------------------- */

rule WindowsShell_s3 {
	meta:
		description = "Detects simple Windows shell - file s3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		id = "064754a7-8639-5dbd-93f3-906662b8e9bc"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v3" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "put <local> <remote> - upload file" fullword ascii
		$s7 = "term                 - terminate remote client" fullword ascii
		$s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s9 = "-l           Listen for incoming connections" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindosShell_s1 {
	meta:
		description = "Detects simple Windows shell - file s1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		id = "b4e783a2-4a93-5c72-9b09-4692b383ac00"
	strings:
		$s1 = "[ executing cmd.exe" fullword ascii
		$s2 = "[ simple remote shell for windows v1" fullword ascii
		$s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
		$s4 = "usage: s1 <address> [options]" fullword ascii
		$s5 = "[ waiting for connections on %s" fullword ascii
		$s6 = "-l           Listen for incoming connections" fullword ascii
		$s7 = "[ connection from %s" fullword ascii
		$s8 = "[ %c%c requires parameter" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindowsShell_s4 {
	meta:
		description = "Detects simple Windows shell - file s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "838771dc-f885-5332-9813-2bc01af8e5fe"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v4" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s8 = "-l           Listen for incoming connections" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule WindowsShell_Gen {
	meta:
		description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
		hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
		hash4 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash5 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "6b871e8a-8fe3-5cc6-9f2c-ba2359861ea1"
	strings:
		$s0 = "[ %c%c requires parameter" fullword ascii
		$s1 = "[ %s : %i" fullword ascii
		$s2 = "[ %s : %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( all of them )
}

rule WindowsShell_Gen2 {
	meta:
		description = "Detects simple Windows shell - from files s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "8ed8443d-491b-5cb0-b12b-0d25267ba462"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "get <remote> <local> - download file" fullword ascii
		$s3 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s4 = "put <local> <remote> - upload file" fullword ascii
		$s5 = "term                 - terminate remote client" fullword ascii
		$s6 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ error : received %i bytes" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}
