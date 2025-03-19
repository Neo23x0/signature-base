/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-05
	Identifier: Buckeye
*/

/* Rule Set ----------------------------------------------------------------- */

rule HKTL_Buckeye_Osinfo {
	meta:
		description = "Detects OSinfo tool used by the Buckeye APT group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"
		date = "2016-09-05"
		score = 70
		id = "e40a86d1-fd1a-5430-b7b7-8cc7ca128cc5"
	strings:
		$s1 = "-s ShareInfo ShareDir" fullword ascii
		$s2 = "-a Local And Global Group User Info" fullword ascii
		$s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
		$s4 = "info <\\server> <user>" fullword ascii
		$s5 = "-c Connect Test" fullword ascii
		$s6 = "-gd Group Domain Admins" fullword ascii
		$s7 = "-n NetuseInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and 3 of ($s*)
}

rule HKTL_RemoteCmd {
	meta:
		description = "Detects a remote access tool used by APT groups - file RemoteCmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		modified = "2022-12-21"
		score = 70
		hash1 = "5264d1de687432f8346617ac88ffcb31e025e43fc3da1dad55882b17b44f1f8b"
		id = "384f37f3-4562-5d79-9793-0384c43d4602"
	strings:
		$s1 = "RemoteCmd.exe" fullword wide
		$s2 = "\\Release\\RemoteCmd.pdb" ascii
		$s3 = "RemoteCmd [ComputerName] [Executable] [Param1] [Param2] ..." fullword wide
		$s4 = "http://{0}:65101/CommandEngine" fullword wide
		$s5 = "Brenner.RemoteCmd.Client" fullword ascii
		$s6 = "$b1888995-1ee5-4f6d-82df-d2ab8ae73d63" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and 2 of them ) or ( 4 of them )
}

rule HKTL_ChromePass {
	meta:
		description = "Detects a tool used by APT groups - file ChromePass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		modified = "2025-03-10"
		score = 75
		hash1 = "5ff43049ae18d03dcc74f2be4a870c7056f6cfb5eb636734cca225140029de9a"
		id = "950b9761-bdfd-514b-90ea-a1454d35ce5a"
	strings:
		$x1 = "\\Release\\ChromePass.pdb" ascii
		$x2 = "Windows Protect folder for getting the encryption keys" wide
		$x3 = "Chrome User Data folder where the password file is stored" wide

		$s1 = "Opera Software\\Opera Stable\\Login Data" fullword wide
		$s2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
		$s3 = "Load the passwords from another Windows user or external drive: " fullword wide
		$s4 = "Windows Login Password:" fullword wide
		$s5 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
		$s6 = "Chrome Password Recovery" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) ) or ( 5 of them )
}
