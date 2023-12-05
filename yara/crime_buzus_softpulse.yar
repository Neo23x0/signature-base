
rule Win32_Buzus_Softpulse {
	meta:
		description = "Trojan Buzus / Softpulse"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-13"
		hash = "2f6df200e63a86768471399a74180466d2e99ea9"
		score = 75
		id = "3b555916-030a-5773-b2f1-e995fc81b697"
	strings:
		$x1 = "pi4izd6vp0.com" fullword ascii

		$s1 = "SELECT * FROM Win32_Process" fullword wide
		$s4 = "CurrentVersion\\Uninstall\\avast" fullword wide
		$s5 = "Find_RepeatProcess" fullword ascii
		$s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" wide
		$s7 = "myapp.exe" fullword ascii
		$s14 = "/c ping -n 1 www.google" wide
	condition:
		uint16(0) == 0x5a4d and 
			( 
				( $x1 and 2 of ($s*) ) or
				all of ($s*) 
			)
}
