/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-25
	Identifier: Kaspersky Report on threats involving CVE-2015-2545
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mal_Dropper_httpEXE_from_CAB {
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 60
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
		id = "f67c13e9-67e7-56aa-8ced-55e9bb814971"
	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}

rule Mal_http_EXE {
	meta:
		description = "Detects trojan from APT report named http.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		modified = "2023-01-27"
		score = 80
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"
		id = "bcae9920-56ea-54a1-857b-70c275090e19"
	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" ascii
		$x4 = "\\wordpade.exe" ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii /* base64: pKY1[1 */

		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 2 of ($s*) ) ) or ( 3 of ($x*) )
}

rule Mal_PotPlayer_DLL {
	meta:
		description = "Detects a malicious PotPlayer.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 70
		hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"
		id = "71d34266-63e0-5a97-9a80-952be917641a"
	strings:
		$x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii

		$s3 = "PotPlayer.dll" fullword ascii
		$s4 = "\\update.dat" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and $x1 or all of ($s*)
}
