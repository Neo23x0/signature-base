/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2015-06-02
	Identifier: APT28
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT28_CHOPSTICK {
	meta:
		description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/v3ebal"
		date = "2015-06-02"
		hash = "f4db2e0881f83f6a2387ecf446fcb4a4c9f99808"
		score = 60
		id = "08bc4cc2-1844-5218-bb89-20a3ac70a951"
	strings:
		$s0 = "jhuhugit.tmp" fullword ascii /* score: '14.005' */
		$s8 = "KERNEL32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 14405 times */
		$s9 = "IsDebuggerPresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3518 times */
		$s10 = "IsProcessorFeaturePresent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1383 times */
		$s11 = "TerminateProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13081 times */
		$s13 = "DeleteFileA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 1384 times */
		$s15 = "GetProcessHeap" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5875 times */
		$s16 = "!This program cannot be run in DOS mode." fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 20908 times */
		$s17 = "LoadLibraryA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 5461 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 722KB and all of them
}

rule APT28_SourFace_Malware1 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		hash1 = "e2450dffa675c61aa43077b25b12851a910eeeb6"
		hash2 = "d9c53adce8c35ec3b1e015ec8011078902e6800b"
		score = 60
		id = "d4275b8d-384f-58b7-bac5-05fb7db659e2"
	strings:
		$s0 = "coreshell.dll" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "Core Shell Runtime Service" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "\\chkdbg.log" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule APT28_SourFace_Malware2 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		super_rule = 1
		hash0 = "367d40465fd1633c435b966fa9b289188aa444bc"
		hash1 = "cf3220c867b81949d1ce2b36446642de7894c6dc"
		hash2 = "ed48ef531d96e8c7360701da1c57e2ff13f12405"
		hash3 = "682e49efa6d2549147a21993d64291bfa40d815a"
		hash4 = "a8551397e1f1a2c0148e6eadcb56fa35ee6009ca"
		hash5 = "f5b3e98c6b5d65807da66d50bd5730d35692174d"
		score = 60
		id = "8a9df742-82c1-56bb-ab70-6384403f70b5"
	strings:
		$s0 = "coreshell.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Applicate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule APT28_SourFace_Malware3 {
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		super_rule = 1
		hash0 = "85522190958c82589fa290c0835805f3d9a2f8d6"
		hash1 = "d9c53adce8c35ec3b1e015ec8011078902e6800b"
		hash2 = "367d40465fd1633c435b966fa9b289188aa444bc"
		hash3 = "d87b310aa81ae6254fff27b7d57f76035f544073"
		hash4 = "cf3220c867b81949d1ce2b36446642de7894c6dc"
		hash5 = "ed48ef531d96e8c7360701da1c57e2ff13f12405"
		hash6 = "682e49efa6d2549147a21993d64291bfa40d815a"
		hash7 = "a8551397e1f1a2c0148e6eadcb56fa35ee6009ca"
		hash8 = "f5b3e98c6b5d65807da66d50bd5730d35692174d"
		hash9 = "e2450dffa675c61aa43077b25b12851a910eeeb6"
		score = 60
		id = "b49843b9-3a54-5525-958e-ac545cc00bde"
	strings:
		$s0 = "coreshell.dll" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "Core Shell Runtime Service" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}


import "pe"

rule APT28_SkinnyBoy_Dropper: RUSSIA {
   meta:
      description = "Detects APT28 SkinnyBoy droppers"
      author = "Cluster25"
      date = "2021-05-24"
      reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
      hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
      id = "ed0b2d2b-f820-57b5-9654-c24734d81996"
   strings:
      $ = "cmd /c DEL " ascii
      /* $ = " \"" ascii */ /* slowing down scanning */
      $ = {8a 08 40 84 c9 75 f9}
      $ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}
   condition:
      (uint16(0) == 0x5A4D and all of them)
}

rule APT28_SkinnyBoy_Launcher: RUSSIA {
   meta:
      description = "Detects APT28 SkinnyBoy launchers"
      author = "Cluster25"
      date = "2021-05-24"
      reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
      hash1 ="2a652721243f29e82bdf57b565208c59937bbb6af4ab51e7b6ba7ed270ea6bce"
      id = "eaf4e8e5-cbec-5000-a2ff-31d1dac4c30f"
   strings:
      $sha = {F4 EB 56 52 AF 4B 48 EE 08 FF 9D 44 89 4B D5 66 24 61 2A 15 1D 58 14 F9 6D 97
      13 2C 6D 07 6F 86}
      $l1 = "CryptGetHashParam" ascii
      $l2 = "CryptCreateHash" ascii
      $l3 = "FindNextFile" ascii
      $l4 = "PathAddBackslashW" ascii
      $l5 = "PathRemoveFileSpecW" ascii
      $h1 = {50 6A 00 6A 00 68 0C 80 00 00 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00
      56 ?? ?? ?? ?? 50 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??}
      $h2 = {8B 01 3B 02 75 10 83 C1 04 83 C2 04 83 EE 04 73 EF}
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and ($sha or (all of ($l*) and all of ($h*)))
}

rule APT28_SkinnyBoy_Implanter: RUSSIA {
   meta:
      description = "Detects APT28 SkinnyBoy implanter"
      author = "Cluster25"
      date = "2021-05-24"
      reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
      hash1 = "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"
      id = "c44faf95-a64c-58f4-97d4-2fe17aefc813"
   strings:
      $enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
      85 [4] 6A ?? 50 66 [7] E8}
      $heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
      $xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }
   condition:
      uint16(0) == 0x5a4d and pe.is_dll() and filesize < 100KB and $xor_cycle and $heap_ops and
      $enc_string
}
