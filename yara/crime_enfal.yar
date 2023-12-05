rule MAL_Enfal_Nov22 { 
   meta:
      old_rule_name = "Enfal_Malware"
      description = "Detects a certain type of Enfal Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
      date = "2015-02-10"
      modified = "2023-01-06"
      hash2 = "42fa6241ab94c73c7ab386d600fae70da505d752daab2e61819a0142b531078a"
      hash2 = "bf433f4264fa3f15f320b35e773e18ebfe94465d864d3f4b2a963c3e5efd39c2"
      score = 75
      id = "9dcba14e-2175-5da0-8629-5b952c213f6c"
   strings:
      $xop1 = { 00 00 83 c9 ff 33 c0 f2 ae f7 d1 49 b8 ff 8f 01 00 2b c1 }

      $s1 = "POWERPNT.exe" fullword ascii
      $s2 = "%APPDATA%\\Microsoft\\Windows\\" ascii
      $s3 = "%HOMEPATH%" fullword ascii
      $s4 = "Server2008" fullword ascii
      $s5 = "%ComSpec%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( 1 of ($x*) or 3 of ($s*) )
}

rule Enfal_Malware_Backdoor {
	meta:
		description = "Generic Rule to detect the Enfal Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015/02/10"
		super_rule = 1
		hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
		hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
		hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
		score = 60
		id = "4631888c-e1e2-5969-a312-0f0011cd605c"
	strings:
		$x1 = "Micorsoft Corportation" fullword wide
		$x2 = "IM Monnitor Service" fullword wide

		$s1 = "imemonsvc.dll" fullword wide
		$s2 = "iphlpsvc.tmp" fullword

		$z1 = "urlmon" fullword
		$z2 = "Registered trademarks and service marks are the property of their respec" wide
		$z3 = "XpsUnregisterServer" fullword
		$z4 = "XpsRegisterServer" fullword
		$z5 = "{53A4988C-F91F-4054-9076-220AC5EC03F3}" fullword
	condition:
		uint16(0) == 0x5a4d and
		(
			1 of ($x*) or
			( all of ($s*) and all of ($z*) )
		)
}
