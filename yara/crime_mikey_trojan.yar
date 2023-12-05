
rule Gen_Trojan_Mikey {
	meta:
		description = "Trojan Mikey - file sample_mikey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-07"
		hash = "a8e6c3ca056b3ff2495d7728654b780735b3a4cb"
		score = 70
		id = "ff875436-4fed-5f20-a0a5-bfd146d93499"
	strings:
		$s0 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" fullword ascii 
						/* reversed string 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' */
		$x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.0; MyIE 3.01)" fullword ascii
		$x3 = "%d*%u%s" fullword ascii
		$x4 = "%s %s:%d" fullword ascii
		$x5 = "Mnopqrst Vwxyabcde Ghijklm Opqrstuv Xya" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $s0 and 2 of ($x*)
}

