
rule PoisonIvy_Generic_3 {
	meta:
		description = "PoisonIvy RAT Generic Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-14"
		hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"
		id = "0f6a47ee-b741-59cc-b2d6-6bf3989ce8e7"
	strings:
		$k1 = "Tiger324{" fullword ascii
		
		$s2 = "WININET.dll" fullword ascii
		$s3 = "mscoree.dll" fullword wide
		$s4 = "WS2_32.dll" fullword
		$s5 = "Explorer.exe" fullword wide
		$s6 = "USER32.DLL"
		$s7 = "CONOUT$"
		$s8 = "login.asp"
		
		$h1 = "HTTP/1.0"
		$h2 = "POST"
		$h3 = "login.asp"
		$h4 = "check.asp"
		$h5 = "result.asp"
		$h6 = "upload.asp"
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and
			( 
				$k1 or all of ($s*) or all of ($h*)
			)
}
