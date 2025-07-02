/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-10
	Identifier: Winnti Malware
*/
import "pe"

rule Winnti_signing_cert {
	meta:
		description = "Detects a signing certificate used by the Winnti APT group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
		date = "2015-10-10"
		score = 75
		hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		id = "0cf185eb-fb8d-5e1f-9089-4f36eb4798de"
	strings:
		$s1 = "Guangzhou YuanLuo Technology Co." ascii
		$s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
		$s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule Winnti_malware_Nsiproxy {
	meta:
		description = "Detects a Winnti rootkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-10-10"
		score = 75
		hash1 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash2 = "cf1e006694b33f27d7c748bab35d0b0031a22d193622d47409b6725b395bffb0"
		hash3 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash4 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
		hash5 = "ba7ccd027fd2c826bbe8f2145d5131eff906150bd98fe25a10fbee2c984df1b8"
		id = "9b14541c-6077-5f3b-8f73-ff3d283bf209"
	strings:
		$x1 = "\\Driver\\nsiproxy" wide

		$a1 = "\\Device\\StreamPortal" wide
		$a2 = "\\Device\\PNTFILTER" wide

		$s1 = "Cookie: SN=" fullword ascii
		$s2 = "\\BaseNamedObjects\\_transmition_synchronization_" wide
		$s3 = "Winqual.sys" fullword wide
		$s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" wide
		$s5 = "http://www.wasabii.com.tw 0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $x1 and 1 of ($a*) and 2 of ($s*)
}

rule Winnti_malware_UpdateDLL {
	meta:
		description = "Detects a Winnti malware - Update.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		id = "c6896191-d856-55f2-a47f-621a4f10d0c7"
	strings:
		$c1 = "'Wymajtec$Tima Stempijg Sarviges GA -$G2" fullword ascii
		$c2 = "AHDNEAFE1.sys" fullword ascii
		$c3 = "SOTEFEHJ3.sys" fullword ascii
		$c4 = "MainSYS64.sys" fullword ascii

		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\\\.\\pipe\\usbpcex%d" fullword wide
		$s4 = "\\\\.\\pipe\\usbpcg%d" fullword wide
		$s5 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" wide
		$s6 = "\\??\\pipe\\usbpcg%d" fullword wide
		$s7 = "\\??\\pipe\\usbpcex%d" fullword wide
		$s8 = "HOST: %s" fullword ascii
		$s9 = "$$$--Hello" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and
		(
			( 1 of ($c*) and 3 of ($s*) ) or all of ($s*)
		)
}
rule Winnti_malware_FWPK {
   meta:
      description = "Detects a Winnti malware - FWPKCLNT.SYS"
      author = "Florian Roth (Nextron Systems)"
      reference = "VTI research"
      date = "2015-10-10"
      modified = "2023-01-06"
      score = 75
      hash1 = "1098518786c84b0d31f215122275582bdcd1666653ebc25d50a142b4f5dabf2c"
      hash2 = "9a684ffad0e1c6a22db1bef2399f839d8eff53d7024fb014b9a5f714d11febd7"
      hash3 = "a836397817071c35e24e94b2be3c2fa4ffa2eb1675d3db3b4456122ff4a71368"
      id = "591ad72d-b9d4-5cd9-9103-37e001026610"
   strings:
      $s0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" wide
      $s1 = "%x:%d->%x:%d, Flag %s%s%s%s%s, seq %u, ackseq %u, datalen %u" fullword ascii
      $s2 = "FWPKCLNT.SYS" fullword ascii
      $s3 = "Port Layer" fullword wide
      $s4 = "%x->%x, icmp type %d, code %d" fullword ascii
      $s5 = "\\BaseNamedObjects\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28E}" wide
      $s6 = "\\Ndi\\Interfaces" wide
      $s7 = "\\Device\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide
      $s8 = "Bad packet" fullword ascii
      $s9 = "\\BaseNamedObjects\\EKV0000000000" wide
      $s10 = "%x->%x" fullword ascii
      $s11 = "IPInjectPkt" fullword ascii /* Goodware String - occured 6 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 642KB and all of them
}

rule Winnti_malware_StreamPortal_Gen {
	meta:
		description = "Detects a Winnti malware - Streamportal"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash3 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
		id = "f9d31d6b-a6f7-5359-b741-960b678e0b9c"
	strings:
		$s0 = "Proxies destination address/port for TCP" fullword wide
		$s3 = "\\Device\\StreamPortal" wide
		$s4 = "Transport-Data Proxy Sub-Layer" fullword wide
		$s5 = "Cookie: SN=" fullword ascii
		$s6 = "\\BaseNamedObjects\\_transmition_synchronization_" wide
		$s17 = "NTOSKRNL.EXE" fullword wide /* Goodware String - occured 4 times */
		$s19 = "FwpsReferenceNetBufferList0" fullword ascii /* Goodware String - occured 5 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 275KB and all of them
}

rule WINNTI_KingSoft_Moz_Confustion {
   meta:
      description = "Detects Barium sample with Copyright confusion"
      author = "Markus Neis"
      reference = "https://www.virustotal.com/en/file/070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496/analysis/"
      date = "2018-04-13"
      hash1 = "070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496"
      id = "0c45c1ff-6734-504f-91d1-cf5d6744252f"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         pe.imphash() == "7f01b23ccfd1017249c36bc1618d6892" or
         (
            pe.version_info["LegalCopyright"] contains "Mozilla Corporation"
            and pe.version_info["ProductName"] contains "Kingsoft"
         )
      )
}
rule APT_Winnti_MAL_Dec19_1 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      modified = "2025-06-03"
      score = 75
      id = "322e9362-bfb6-55e3-9a93-d54246311d11"
   strings:
      $e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
      $e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
      $e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
      $e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
      $e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase

      $fp1 = "also increase possible memory usage of THOR."
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($e*) and not 1 of ($fp*)

}

rule APT_Winnti_MAL_Dec19_2 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      score = 75
      id = "77f2cb7d-90a6-5654-9d2e-6b525cd910a2"
   strings:
      $a1 = "IPSecMiniPort" wide fullword
      $a2 = "ndis6fw" wide fullword
      $a3 = "TCPIP" wide fullword
      $a4 = "NDIS.SYS" ascii fullword
      $a5 = "ntoskrnl.exe" ascii fullword
      $a6 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
      $a7 = "\\Device\\Null" wide
      $a8 = "\\Device" wide
      $a9 = "\\Driver" wide
      $b1 = { 66 81 7? ?? 70 17 }
      $b2 = { 81 7? ?? 07 E0 15 00 }
      $b3 = { 8B 46 18 3D 03 60 15 00 }
   condition:
      (6 of ($a*)) and (2 of ($b*))
}

rule APT_Winnti_MAL_Dec19_3 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      score = 75
      id = "2e001c91-0794-5940-ad8c-8e58a01e100c"
   strings:
      $b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [8-10] 8B ?? 50 41 B9 40 00 00 00 41 B8 00 10 00 00 }
      $b2 = { 8B 40 28 [5-8] 48 03 C8 48 8B C1 [5-8] 48 89 41 28 }
      $b3 = { 48 6B ?? 28 [5-8] 8B ?? ?? 10 [5-8] 48 6B ?? 28 [5-8] 8B ?? ?? 14 }
      $b4 = { 83 B? 90 00 00 00 00 0F 84 [9-12] 83 B? 94 00 00 00 00 0F 84 }
      $b5 = { (45 | 4D) (31 | 33) C0 BA 01 00 00 00 [10-16] FF 5? 28 [0-1] (84 | 85) C0 }
   condition:
      (4 of ($b*))
}

rule APT_Winnti_MAL_Dec19_4 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      score = 75
      id = "1f7ac215-d049-5b97-9797-9589a70cbf2b"
   strings:
      $b1 = { 4C 8D 41 24 33 D2 B9 03 00 1F 00 FF 9? F8 00 00 00 48 85 C0 74 }
      $b2 = { 4C 8B 4? 08 BA 01 00 00 00 49 8B C? FF D0 85 C0 [2-6] C7 4? 1C 01 00 00 00 B8 01 00 00 00 }
      $b3 = { 8B 4B E4 8B 53 EC 41 B8 00 40 00 00 4? 0B C? FF 9? B8 00 00 00 EB }
   condition:
      (2 of ($b*))
}

rule APT_Winnti_MAL_Dec19_5 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      score = 75
      id = "2a8f28e6-5a01-5a2f-b89b-9c34163afcda"
   strings:
      $a1 = "-k netsvcs" ascii
      $a2 = "svchost.exe" ascii fullword
      $a3 = "%SystemRoot%\\System32\\ntoskrnl.exe" ascii
      $a4 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii
      $a5 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii
      $a6 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii
      $a7 = "cmd.exe" wide
      $a8 = ",XML" wide
      $a9 = "\\rundll32.exe" wide
      $a10 = "\\conhost.exe" wide
      $a11 = "\\cmd.exe" wide
      $a12 = "NtQueryInformationProcess" ascii
      $a13 = "Detours!" ascii fullword
      $a14 = "Loading modified build of detours library designed for MPC-HC player (http://sourceforge.net/projects/mpc-hc/)" ascii
      $a15 = "CONOUT$" wide fullword
      $a16 = { C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }
   condition:
      (12 of ($a*))
}

rule APT_CN_Group_Loader_Jan20_1 {
   meta:
      description = "Detects loaders used by Chinese groups"
      author = "Vitali Kremez"
      reference = "https://twitter.com/VK_Intel/status/1223411369367785472?s=20"
      date = "2020-02-01"
      score = 80
      id = "c85ae499-4f76-56ff-877d-887e1a7fc077"
   strings:
      $xc1 = { 8B C3 C1 E3 10 C1 E8 10 03 D8 6B DB 77 83 C3 13 }
   condition:
      1 of them
}

rule winnti_dropper_x64_libtomcrypt_fns : TAU CN APT {
   meta:
      author = "CarbonBlack Threat Research" // tharuyama
      date = "2019-08-26"
      description = "Designed to catch winnti 4.0 loader and hack tool x64"
      rule_version = 1
      yara_version = "3.8.1"
      Confidence = "Prod"
      Priority = "High"
      TLP = "White"
      reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
      exemplar_hashes = "5ebf39d614c22e750bb8dbfa3bcb600756dd3b36929755db9b577d2b653cd2d1"
      sample_md5 = "794E127D627B3AF9015396810A35AF1C"

      id = "080d837c-248f-5718-b4a2-290495cd3b38"
   strings:
      // fn_register_libtomcrypt
      $0x140001820 = { 48 83 EC 28 83 3D ?? ?? ?? ?? 00 }
      $0x140001831 = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
      $0x140001842 = { B8 0B 00 E0 0C 48 83 C4 28 C3 }
      $0x14000184c = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
      $0x140001881 = { B8 0C 00 E0 0C 48 83 C4 28 C3 }
      $0x14000188b = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
      $0x1400018e4 = { B8 0D 00 E0 0C 48 83 C4 28 C3 }
      $0x1400018ee = { 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 41 B8 A0 01 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 }
      $0x140001911 = { 33 C0 48 83 C4 28 C3 }
      // fn_decrypt_PE
      $0x140001670 = { 40 55 56 57 41 55 41 56 41 57 B8 38 12 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 10 12 00 00 48 8B AC 24 90 12 00 00 4C 8B B4 24 A0 12 00 00 45 33 FF 44 39 3D ?? ?? ?? ?? 49 8B F1 41 0F B7 F8 4C 8B EA 44 8B D9 66 44 89 7C 24 40 }
      $0x1400016c8 = { B8 01 00 E0 0C }
      $0x1400016d2 = { 48 89 9C 24 30 12 00 00 4D 85 C9 }
      $0x1400016ec = { 8B 9C 24 98 12 00 00 83 FB 01 }
      $0x1400016fc = { 48 8D 54 24 40 }
      $0x140001701 = { 4C 89 A4 24 28 12 00 00 E8 ?? ?? ?? ?? 44 0F B7 64 24 40 66 44 3B E7 }
      $0x140001727 = { 48 8D 54 24 40 41 8B CB E8 ?? ?? ?? ?? 0F B7 94 24 A8 12 00 00 66 39 54 24 40 }
      $0x140001750 = { 41 8B CB E8 ?? ?? ?? ?? 8B F8 83 F8 FF }
      $0x14000175f = { B8 0F 00 E0 0C }
      $0x140001764 = { 4C 8B A4 24 28 12 00 00 }
      $0x14000176c = { 48 8B 9C 24 30 12 00 00 }
      $0x140001774 = { 48 8B 8C 24 10 12 00 00 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 38 12 00 00 41 5F 41 5E 41 5D 5F 5E 5D C3 }
      $0x140001795 = { 48 8D 4C 24 54 33 D2 41 B8 B4 11 00 00 44 89 7C 24 50 E8 ?? ?? ?? ?? 48 8D 44 24 50 48 89 44 24 30 45 0F B7 CC 4D 8B C5 49 8B D6 8B CF 44 89 7C 24 28 44 89 7C 24 20 E8 ?? ?? ?? ?? 85 C0 }
      $0x1400017d5 = { 4C 8D 4C 24 50 44 8B C3 48 8B D5 48 8B CE E8 ?? ?? ?? ?? 48 8D 4C 24 50 8B D8 E8 ?? ?? ?? ?? 8B C3 }
      $0x1400017fb = { B8 04 00 E0 0C }
      $0x140001805 = { B8 03 00 E0 0C }
      $0x14000180f = { B8 02 00 E0 0C }

   condition:
      all of them
}

rule winnti_dropper_x86_libtomcrypt_fns : TAU CN APT {
   meta:
      author = "CarbonBlack Threat Research" // tharuyama
      date = "2019-08-26"
      description = "Designed to catch winnti 4.0 loader and hack tool x86"
      rule_version = 1
      yara_version = "3.8.1"
      confidence = "Prod"
      oriority = "High"
      TLP = "White"
      reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
      exemplar_hashes = "0fdcbd59d6ad41dda9ae8bab8fad9d49b1357282027e333f6894c9a92d0333b3"
      sample_md5 = "da3b64ec6468a4ec56f977afb89661b1"

      id = "48e7a3b0-55c7-5db5-855f-1614bd00afb4"
   strings:
      // fn_register_libtomcrypt
      $0x401d20 = { 8B 0D ?? ?? ?? ?? 33 C0 85 C9 }
      $0x401d30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 ?? }
      $0x401d46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 ?? }
      $0x401d76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 83 F8 ?? }
      $0x401dc4 = { 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 33 C0 F3 A5 5F C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5E C3 }
      // fn_decrypt_PE
      $0x401bd0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 56 57 85 C0 C7 45 FC ?? ?? ?? ?? }
      $0x401bf4 = { 8B 45 14 85 C0 }
      $0x401bff = { 8B 45 18 85 C0 }
      $0x401c14 = { 8B 7D 08 8D 45 FC 50 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 08 66 }
      $0x401c31 = { 8B 45 0C 85 C0 }
      $0x401c3c = { 8D 4D FC 51 57 E8 ?? ?? ?? ?? 66 8B 55 FC 83 C4 08 66 3B 55 24 }
      $0x401c57 = { 8B 5D 20 85 DB }
      $0x401c62 = { 57 E8 ?? ?? ?? ?? 8B D0 83 C4 04 83 FA ?? }
      $0x401c72 = { B9 ?? ?? ?? ?? 33 C0 8D BD 48 EE FF FF C7 85 44 EE FF FF ?? ?? ?? ?? F3 AB 8B 4D 0C 8D 85 44 EE FF FF 50 6A ?? 81 E6 FF FF 00 00 6A ?? 56 51 53 52 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 }
      $0x401caf = { 8B 45 1C 8B 4D 18 8D 95 44 EE FF FF 52 8B 55 14 50 51 52 E8 ?? ?? ?? ?? 8B F0 8D 85 44 EE FF FF 50 E8 ?? ?? ?? ?? 83 C4 14 8B C6 5F 5E 5B 8B E5 5D C3 }
      $0x401ce1 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401ced = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401cf9 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401d05 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401d16 = { 5F 5E 5B 8B E5 5D C3 }

   condition:
      all of them
}
