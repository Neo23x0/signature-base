
/* SnowGlobe Babar ---------------------------------------------------------- */

rule SNOWGLOBE_Babar_Malware {
	meta:
		description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
		date = "2015/02/18"
		hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
		score = 80
		id = "53a61065-a3b3-563e-8ecc-513d8da68085"
	strings:
		$z0 = "admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper" ascii fullword
		$z1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;" ascii fullword
		$z2 = "ExecQueryFailled!" fullword ascii
		$z3 = "NBOT_COMMAND_LINE" fullword
		$z4 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" fullword

		$s1 = "/s /n %s \"%s\"" fullword ascii
		$s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
		$s3 = "/c start /wait " fullword ascii
		$s4 = "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)" ascii

		$x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" ascii
		$x2 = "%COMMON_APPDATA%" fullword ascii
		$x4 = "CONOUT$" fullword ascii
		$x5 = "cmd.exe" fullword ascii
		$x6 = "DLLPATH" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1MB and
		(
			( 1 of ($z*) and 1 of ($x*) ) or
			( 3 of ($s*) and 4 of ($x*) )
		)
}
