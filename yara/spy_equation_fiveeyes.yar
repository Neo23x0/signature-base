/* Equation APT ------------------------------------------------------------ */

rule apt_equation_exploitlib_mutexes {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
		date = "2016-02-15"
        modified = "2023-01-27"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        id = "d060bfd7-fb16-55d3-8a39-1197fdd8e759"
    strings:
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
    condition:
        uint16(0) == 0x5A4D and any of ($a*)
}

/* Disabled by FR due to $a2 string
rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}
*/

rule apt_equation_equationlaser_runtimeclasses {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the EquationLaser malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "https://securelist.com/blog/"
	    id = "924c80ca-3607-57aa-85a2-b33ff52b0c1b"
	strings:
	    $a1="?a73957838_2@@YAXXZ"
	    $a2="?a84884@@YAXXZ"
	    $a3="?b823838_9839@@YAXXZ"
	    $a4="?e747383_94@@YAXXZ"
	    $a5="?e83834@@YAXXZ"
	    $a6="?e929348_827@@YAXXZ"
	condition:
	    any of them
}

rule apt_equation_cryptotable {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the crypto library used in Equation group malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "https://securelist.com/blog/"
	    id = "e7f313a3-8ef8-5363-898a-836a96aaa2ff"
	strings:
	    $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
	condition:
	    $a
}

/* Equation Group - Kaspersky ---------------------------------------------- */

rule Equation_Kaspersky_TripleFantasy_1 {
	meta:
		description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
		id = "8d2adb3c-70e0-5768-bcfa-be64220064d9"
	strings:
		$s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
		$s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
		$s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
		$s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
		$s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
		$s5 = "Chrome" fullword wide
		$s6 = "StringIndex" fullword ascii

		$x1 = "itemagic.net@443" fullword wide
		$x2 = "team4heat.net@443" fullword wide
		$x5 = "62.216.152.69@443" fullword wide
		$x6 = "84.233.205.37@443" fullword wide

		$z1 = "www.microsoft.com@80" fullword wide
		$z2 = "www.google.com@80" fullword wide
		$z3 = "127.0.0.1:3128" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300000 and
		(
			( all of ($s*) and all of ($z*) ) or
			( all of ($s*) and 1 of ($x*) )
		)
}

rule Equation_Kaspersky_DoubleFantasy_1 {
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
		id = "f3c87adf-86c3-5d7c-9532-75341841869a"
	strings:
		$z1 = "msvcp5%d.dll" fullword ascii

		$s0 = "actxprxy.GetProxyDllInfo" fullword ascii
		$s3 = "actxprxy.DllGetClassObject" fullword ascii
		$s5 = "actxprxy.DllRegisterServer" fullword ascii
		$s6 = "actxprxy.DllUnregisterServer" fullword ascii

		$x2 = "191H1a1" fullword ascii
		$x3 = "November " fullword ascii
		$x4 = "abababababab" fullword ascii
		$x5 = "January " fullword ascii
		$x6 = "October " fullword ascii
		$x7 = "September " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 350000 and
		(
			( $z1 ) or
			( all of ($s*) and 6 of ($x*) )
		)
}

rule Equation_Kaspersky_GROK_Keylogger {
	meta:
		description = "Equation Group Malware - GROK keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
		id = "1bae3e86-54e5-55e9-8bbd-aa9ec2a0fa2b"
	strings:
		$s0 = "c:\\users\\rmgree5\\" ascii
		$s1 = "msrtdv.sys" fullword wide

		$x1 = "svrg.pdb" fullword ascii
		$x2 = "W32pServiceTable" fullword ascii
		$x3 = "In forma" fullword ascii
		$x4 = "ReleaseF" fullword ascii
		$x5 = "criptor" fullword ascii
		$x6 = "astMutex" fullword ascii
		$x7 = "ARASATAU" fullword ascii
		$x8 = "R0omp4ar" fullword ascii

		$z1 = "H.text" fullword ascii
		$z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 250000 and
		(
			$s0 or
			( $s1 and 6 of ($x*) ) or
			( 6 of ($x*) and all of ($z*) )
		)
}

rule Equation_Kaspersky_GreyFishInstaller {
	meta:
		description = "Equation Group Malware - Grey Fish"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
		id = "ea16b51c-755e-5f08-a209-d21a1ed30fcf"
	strings:
		$s0 = "DOGROUND.exe" fullword wide
		$s1 = "Windows Configuration Services" fullword wide
		$s2 = "GetMappedFilenameW" fullword ascii
	condition:
		all of them
}

rule Equation_Kaspersky_EquationDrugInstaller {
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		id = "fa549e6e-f0d8-55ea-9ec9-c8ec53b55dec"
	strings:
		$s0 = "\\system32\\win32k.sys" wide
		$s1 = "ALL_FIREWALLS" fullword ascii

		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller {
   meta:
      description = "Equation Group Malware - EquationLaser Installer"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/ivt8EW"
      date = "2015/02/16"
      hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
      score = 80
      id = "15fd5668-36f2-556c-8150-225d3cbd4121"
   strings:
      $s0 = "Failed to get Windows version" fullword ascii
      $s1 = "lsasrv32.dll and lsass.exe" fullword wide
      $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
      $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
      $s4 = "lsasrv32.dll" fullword ascii
      /* $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii */ /* Modified by Florian Roth */
      $s6 = "%s %02x %s" fullword ascii
      $s7 = "VIEWERS" fullword ascii
      $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
   condition:
      ( uint16(0) == 0x5a4d ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_FannyWorm {
   meta:
      description = "Equation Group Malware - Fanny Worm"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/ivt8EW"
      date = "2015-02-16"
      modified = "2023-01-06"
      hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"
      score = 80
      id = "1b8d1ce6-8926-5aa3-8fba-6a8451d66a7d"
   strings:

      $s1 = "x:\\fanny.bmp" fullword ascii
      $s2 = "32.exe" fullword ascii
      $s3 = "d:\\fanny.bmp" fullword ascii

      $x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
      $x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
      $x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
      $x4 = "\\system32\\win32k.sys" wide
      $x5 = "\\AGENTCPD.DLL" ascii
      $x6 = "agentcpd.dll" fullword ascii
      $x7 = "PADupdate.exe" fullword ascii
      $x8 = "dll_installer.dll" fullword ascii
      $x9 = "\\restore\\" ascii
      $x10 = "Q:\\__?__.lnk" fullword ascii
      $x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
      $x12 = "\\shelldoc.dll" ascii
      $x13 = "file size = %d bytes" fullword ascii
      $x14 = "\\MSAgent" ascii
      $x15 = "Global\\RPCMutex" fullword ascii
      $x16 = "Global\\DirectMarketing" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d ) and filesize < 300000 and
      (
         ( 2 of ($s*) ) or
         ( 1 of ($s*) and 6 of ($x*) ) or
         ( 14 of ($x*) )
      )
}

rule Equation_Kaspersky_HDD_reprogramming_module {
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		id = "09ffe270-39e7-5225-b4a9-1c8d312a09c1"
	strings:
		$s0 = "nls_933w.dll" fullword ascii

		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package {
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		id = "2eb97873-a415-57be-a8fb-70ef86a99c9b"
	strings:
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100000 and all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_Loader {
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
		id = "562e7855-f011-5985-91c0-622b2fec32f8"
	strings:
		$x1 = "Original Innovations, LLC" fullword wide
		$x2 = "Moniter Resource Protocol" fullword wide
		$x3 = "ahlhcib.dll" fullword wide

		$s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		$s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
		$s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		$s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		$s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		$s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}

/* Rule generated from the mentioned keywords */

rule Equation_Kaspersky_SuspiciousString {
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/17"
		score = 60
		id = "a5f203a7-0c50-5658-89f4-44533ed4eef0"
	strings:
		$s1 = "i386\\DesertWinterDriver.pdb" fullword
		$s2 = "Performing UR-specific post-install..."
		$s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
		$s4 = "STRAITSHOOTER30.exe"
		$s5 = "standalonegrok_2.1.1.1"
		$s6 = "c:\\users\\rmgree5\\"
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*)
}

/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */

rule EquationDrug_NetworkSniffer1 {
   meta:
      description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
      id = "21a500e7-3011-50e6-b685-f4f65d6dee17"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s3 = "sys\\mstcp32.dbg" fullword ascii
      $s7 = "mstcp32.sys" fullword wide
      $s8 = "p32.sys" fullword ascii
      $s9 = "\\Device\\%ws_%ws" wide
      $s10 = "\\DosDevices\\%ws" wide
      $s11 = "\\Device\\%ws" wide
   condition:
      all of them
}

rule EquationDrug_CompatLayer_UnilayDLL {
	meta:
		description = "EquationDrug - Unilay.DLL"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "a3a31937956f161beba8acac35b96cb74241cd0f"
		id = "32fd31c7-cc44-50e1-8888-b9da59ce587b"
	strings:
		$s0 = "unilay.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $s0
}

// shitty rule
// rule EquationDrug_HDDSSD_Op : FILE {
//    meta:
//       description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
//       author = "Florian Roth"
//       reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
//       date = "2015/03/11"
//       modified = "2021-01-19"
//       hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
//    strings:
//       $s0 = "nls_933w.dll" fullword ascii
//    condition:
//       all of them
// }

rule EquationDrug_NetworkSniffer2 {
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"
		id = "afc5ae23-4965-5796-af3b-9e2705aea455"
	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "sys\\tdip.dbg" fullword ascii
		$s4 = "dip.sys" fullword ascii
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "\\DosDevices\\%ws" wide
		$s7 = "\\Device\\%ws" wide
	condition:
		all of them
}

rule EquationDrug_NetworkSniffer3 {
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "14599516381a9646cd978cf962c4f92386371040"
		id = "c6b1658b-cbc6-535a-a3a2-15ce3cf6e4f6"
	strings:
		$s0 = "Corporation. All rights reserved." fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "tdip.pdb" fullword ascii
	condition:
		all of them
}

rule EquationDrug_VolRec_Driver {
	meta:
		description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"
		id = "db4f3f65-bdc4-565d-ad59-25a16ec7c9d2"
	strings:
		$s0 = "msrstd.sys" fullword wide
		$s1 = "msrstd.pdb" fullword ascii
		$s2 = "msrstd driver" fullword wide
	condition:
		all of them
}

rule EquationDrug_KernelRootkit {
   meta:
      description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"
      id = "92491e30-4041-5c8b-8e4e-7bc2b1d3234b"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "Parmsndsrv.dbg" fullword ascii
      $s2 = "\\Registry\\User\\CurrentUser\\" wide
      $s3 = "msndsrv.sys" fullword wide
      $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" wide
      $s6 = "\\Device\\%ws_%ws" wide
      $s7 = "\\DosDevices\\%ws" wide
      $s9 = "\\Device\\%ws" wide
   condition:
      all of them
}

rule EquationDrug_Keylogger {
	meta:
		description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
		id = "57b6af34-577b-58ec-9a9e-91911c32270b"
	strings:
		$s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
		$s3 = "\\DosDevices\\Gk" wide
		$s5 = "\\Device\\Gk0" wide
	condition:
		all of them
}

rule EquationDrug_NetworkSniffer4 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"
      id = "12bb1eb3-a14e-5616-bc7c-249c83f97035"
   strings:
      $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
      $s1 = "\\systemroot\\" ascii
      $s2 = "RAVISENT Technologies Inc." fullword wide
      $s3 = "Created by VIONA Development" fullword wide
      $s4 = "\\Registry\\User\\CurrentUser\\" wide
      $s5 = "\\device\\harddiskvolume" wide
      $s7 = "ATMDKDRV.SYS" fullword wide
      $s8 = "\\Device\\%ws_%ws" wide
      $s9 = "\\DosDevices\\%ws" wide
      $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
      $s11 = "\\Device\\%ws" wide
      $s13 = "CineMaster C 1.1 WDM" fullword wide
   condition:
      all of them
}

rule EquationDrug_PlatformOrchestrator {
	meta:
		description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "febc4f30786db7804008dc9bc1cebdc26993e240"
		id = "ce19ed3c-9dd9-5cb0-99fe-c04fde057293"
	strings:
		$s0 = "SERVICES.EXE" fullword wide
		$s1 = "\\command.com" wide
		$s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s3 = "LSASS.EXE" fullword wide
		$s4 = "Windows Configuration Services" fullword wide
		$s8 = "unilay.dll" fullword ascii
	condition:
		all of them
}

rule EquationDrug_NetworkSniffer5 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
      id = "9eac2c51-3ad7-5346-a985-39733bc204c2"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "atmdkdrv.sys" fullword wide
      $s4 = "\\Device\\%ws_%ws" wide
      $s5 = "\\DosDevices\\%ws" wide
      $s6 = "\\Device\\%ws" wide
   condition:
      all of them
}

rule EquationDrug_FileSystem_Filter {
	meta:
		description = "EquationDrug - Filesystem filter driver - volrec.sys, scsi2mgr.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"
		id = "7077daf6-3d51-5ff2-bc74-95cb169a7cd2"
	strings:
		$s0 = "volrec.sys" fullword wide
		$s1 = "volrec.pdb" fullword ascii
		$s2 = "Volume recognizer driver" fullword wide
	condition:
		all of them
}

rule apt_equation_keyword {
    meta:
        description = "Rule to detect Equation group's keyword in executable file"
        last_modified = "2015-09-26"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        id = "a7d4eda5-f390-5099-9c46-bf74a878b4f0"
    strings:
         $a1 = "Backsnarf_AB25" wide
         $a2 = "Backsnarf_AB25" ascii
    condition:
         uint16(0) == 0x5a4d and 1 of ($a*)
}
