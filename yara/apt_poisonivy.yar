
rule PoisonIvy_Sample_APT {
	meta:
		description = "Detects a PoisonIvy APT malware group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b874b76ff7b281c8baa80e4a71fc9be514093c70"
		id = "8d3b8222-8949-57dc-99b7-092189416efd"
	strings:
		$s0 = "pidll.dll" fullword ascii /* score: '11.02' */
		$s1 = "sens32.dll" fullword wide /* score: '11.015' */
		$s3 = "FileDescription" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19311 times */
		$s4 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
		$s5 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
		$s9 = "Microsoft Media Device Service Provider" fullword wide /* score: '-3' */ /* Goodware String - occured 8 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 47KB and all of them
}


rule PoisonIvy_Sample_APT_2 {
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "333f956bf3d5fc9b32183e8939d135bc0fcc5770"
		id = "4d64ccd2-add8-5749-8178-f2c5336e1495"
	strings:
		$s0 = "pidll.dll" fullword ascii /* score: '11.02' */
		$s1 = "sens32.dll" fullword wide /* score: '11.015' */
		$s2 = "9.0.1.56" fullword wide /* score: '9.5' */
		$s3 = "FileDescription" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19311 times */
		$s4 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
		$s5 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
		$s6 = "\"%=%14=" fullword ascii /* score: '4.5' */
		$s7 = "091A1G1R1_1g1u1z1" fullword ascii /* score: '4' */ /* Goodware String - occured 1 times */
		$s8 = "gHsMZz" fullword ascii /* score: '3.005' */
		$s9 = "Microsoft Media Device Service Provider" fullword wide /* score: '-3' */ /* Goodware String - occured 8 times */
		$s10 = "Copyright (C) Microsoft Corp." fullword wide /* score: '-7' */ /* Goodware String - occured 12 times */
		$s11 = "MFC42.DLL" fullword ascii /* score: '-31' */ /* Goodware String - occured 36 times */
		$s12 = "MSVCRT.dll" fullword ascii /* score: '-235' */ /* Goodware String - occured 240 times */
		$s13 = "SpecialBuild" fullword wide /* score: '-1561' */ /* Goodware String - occured 1566 times */
		$s14 = "PrivateBuild" fullword wide /* score: '-1585' */ /* Goodware String - occured 1590 times */
		$s15 = "Comments" fullword wide /* score: '-2149' */ /* Goodware String - occured 2154 times */
		$s16 = "040904b0" fullword wide /* score: '-2365' */ /* Goodware String - occured 2370 times */
		$s17 = "LegalTrademarks" fullword wide /* score: '-3518' */ /* Goodware String - occured 3523 times */
		$s18 = "CreateThread" fullword ascii /* score: '-3909' */ /* Goodware String - occured 3914 times */
		$s19 = "ntdll.dll" fullword ascii /* score: '-4675' */ /* Goodware String - occured 4680 times */
		$s20 = "_adjust_fdiv" ascii /* score: '-5450' */ /* Goodware String - occured 5455 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 47KB and all of them
}

rule PoisonIvy_Sample_APT_3 {
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
		id = "e2e0bf75-7704-585f-b2b3-727d14946c76"
	strings:
		$s0 = "\\notepad.exe" ascii /* score: '11.025' */
		$s1 = "\\RasAuto.dll" ascii /* score: '11.025' */
		$s3 = "winlogon.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13 times */
	condition:
		uint16(0) == 0x5a4d and all of them
}


rule PoisonIvy_Sample_APT_4 {
	meta:
		description = "Detects a PoisonIvy Sample APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "558f0f0b728b6da537e2666fbf32f3c9c7bd4c0c"
		id = "02bf546b-99a2-5ffb-8ee7-7bb005ef953b"
	strings:
		$s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
		$s1 = "idll.dll" fullword ascii /* score: '11.02' */
		$s2 = "mgmts.dll" fullword wide /* score: '11.0' */
		$s3 = "Microsoft(R) Windows(R)" fullword wide /* score: '6.025' */
		$s4 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
		$s5 = "Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3 times */
		$s6 = "SetServiceStatus" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 741 times */
		$s7 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
		$s8 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 7 of them
}

rule PoisonIvy_Sample_5 {
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "545e261b3b00d116a1d69201ece8ca78d9704eb2"
		id = "61f7efd4-745a-5f06-a66d-b4b2a2ecc614"
	strings:
		$s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
		$s2 = "pidll.dll" fullword ascii /* score: '11.02' */
		$s3 = "\\mspmsnsv.dll" ascii /* score: '11.005' */
		$s4 = "\\sfc.exe" ascii /* score: '11.005' */
		$s13 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
		$s15 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
		$s17 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 336 times */
condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}


rule PoisonIvy_Sample_6 {
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash1 = "8c2630ab9b56c00fd748a631098fa4339f46d42b"
		hash2 = "36b4cbc834b2f93a8856ff0e03b7a6897fb59bd3"
		id = "f364fad0-3684-5500-b21b-396f1e259217"
	strings:
		$x1 = "124.133.252.150" fullword ascii /* score: '9.5' */
		$x3 = "http://124.133.254.171/up/up.asp?id=%08x&pcname=%s" fullword ascii /* score: '24.01' */

		$z1 = "\\temp\\si.txt" ascii /* PEStudio Blacklist: strings */ /* score: '27.01' */
		$z2 = "Daemon Dynamic Link Library" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.02' */
		$z3 = "Microsoft Windows CTF Loader" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.03' */
		$z4 = "\\tappmgmts.dll" ascii /* score: '11.005' */
		$z5 = "\\appmgmts.dll" ascii /* score: '11.0' */

		$s0 = "%USERPROFILE%\\AppData\\Local\\Temp\\Low\\ctfmon.log" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.015' */
		$s1 = "%USERPROFILE%\\AppData\\Local\\Temp\\ctfmon.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.015' */
		$s2 = "\\temp\\ctfmon.tmp" ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
		$s3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.025' */
		$s4 = "CONNECT %s:%i HTTP/1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.02' */
		$s5 = "start read histry key" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.04' */
		$s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii /* score: '18.03' */
		$s7 = "[password]%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.025' */
		$s8 = "Daemon.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.02' */
		$s9 = "[username]%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.035' */
		$s10 = "advpack" fullword ascii /* score: '7.005' */
		$s11 = "%s%2.2X" fullword ascii /* score: '7.0' */
		$s12 = "advAPI32" fullword ascii /* score: '6.015' */
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) ) or
		( 8 of ($s*) ) or
		( 1 of ($z*) and 3 of ($s*) )
}

rule PoisonIvy_Sample_7 {
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
		id = "01224053-d95e-5144-981b-76cd7e57e1c3"
	strings:
		$s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
		$s2 = "pidll.dll" fullword ascii /* score: '11.02' */
		$s10 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
		$s11 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
		$s12 = "Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3 times */
		$s13 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-22
	Identifier:
*/

/* Rule Set ----------------------------------------------------------------- */

rule PoisonIvy_RAT_ssMUIDLL {
	meta:
		description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
		author = "Florian Roth (Nextron Systems) (with the help of yarGen and Binarly)"
		reference = "http://goo.gl/WiwtYT"
		date = "2016-04-22"
		hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
		hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
		hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		hash4 = "8b805f508879ecdc9bba711cfbdd570740c4825b969c1b4db980c134ac8fef1c"
		hash5 = "ac99d4197e41802ff9f8852577955950332947534d8e2a0e3b6c1dd1715490d4"
		id = "f2535b70-cf17-5435-9fc8-2dfdf70d95ac"
	strings:
		$s1 = "ssMUIDLL.dll" fullword ascii

		 // 0x10001f81 6a 00	push	0
		 // 0x10001f83 c6 07 e9	mov	byte ptr [edi], 0xe9
		 // 0x10001f86 ff d6	call	esi
		 $op1 = { 6a 00 c6 07 e9 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f81
		 // 0x100012a9 02 cb	add	cl, bl
		 // 0x100012ab 6a 00	push	0
		 // 0x100012ad 88 0f	mov	byte ptr [edi], cl
		 // 0x100012af ff d6	call	esi
		 // 0x100012b1 47	inc	edi
		 // 0x100012b2 ff 4d fc	dec	dword ptr [ebp - 4]
		 // 0x100012b5 75 ??	jne	0x10001290
		 $op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x100012a9
		 // 0x10001f93 6a 00	push	0
		 // 0x10001f95 88 7f 02	mov	byte ptr [edi + 2], bh
		 // 0x10001f98 ff d6	call	esi
		 $op3 = { 6a 00 88 7f 02 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f93

	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and ( all of ($op*) ) ) or ( all of them )
}
