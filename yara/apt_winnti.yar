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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
		date = "2015-10-10"
		score = 75
		hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2015-10-10"
		score = 75
		hash1 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash2 = "cf1e006694b33f27d7c748bab35d0b0031a22d193622d47409b6725b395bffb0"
		hash3 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash4 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
		hash5 = "ba7ccd027fd2c826bbe8f2145d5131eff906150bd98fe25a10fbee2c984df1b8"
	strings:
		$x1 = "\\Driver\\nsiproxy" fullword wide

		$a1 = "\\Device\\StreamPortal" fullword wide
		$a2 = "\\Device\\PNTFILTER" fullword wide

		$s1 = "Cookie: SN=" fullword ascii
		$s2 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
		$s3 = "Winqual.sys" fullword wide
		$s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "http://www.wasabii.com.tw 0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $x1 and 1 of ($a*) and 2 of ($s*)
}

rule Winnti_malware_UpdateDLL {
	meta:
		description = "Detects a Winnti malware - Update.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
	strings:
		$c1 = "'Wymajtec$Tima Stempijg Sarviges GA -$G2" fullword ascii
		$c2 = "AHDNEAFE1.sys" fullword ascii
		$c3 = "SOTEFEHJ3.sys" fullword ascii
		$c4 = "MainSYS64.sys" fullword ascii

		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\\\.\\pipe\\usbpcex%d" fullword wide
		$s4 = "\\\\.\\pipe\\usbpcg%d" fullword wide
		$s5 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "1098518786c84b0d31f215122275582bdcd1666653ebc25d50a142b4f5dabf2c"
		hash2 = "9a684ffad0e1c6a22db1bef2399f839d8eff53d7024fb014b9a5f714d11febd7"
		hash3 = "a836397817071c35e24e94b2be3c2fa4ffa2eb1675d3db3b4456122ff4a71368"
	strings:
		$s0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" fullword wide
		$s1 = "%x:%d->%x:%d, Flag %s%s%s%s%s, seq %u, ackseq %u, datalen %u" fullword ascii
		$s2 = "FWPKCLNT.SYS" fullword ascii
		$s3 = "Port Layer" fullword wide
		$s4 = "%x->%x, icmp type %d, code %d" fullword ascii
		$s5 = "\\BaseNamedObjects\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28E}" fullword wide
		$s6 = "\\Ndi\\Interfaces" fullword wide
		$s7 = "\\Device\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" fullword wide
		$s8 = "Bad packet" fullword ascii
		$s9 = "\\BaseNamedObjects\\EKV0000000000" fullword wide
		$s10 = "%x->%x" fullword ascii
		$s11 = "IPInjectPkt" fullword ascii /* Goodware String - occured 6 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 642KB and all of them
}

rule Winnti_malware_StreamPortal_Gen {
	meta:
		description = "Detects a Winnti malware - Streamportal"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash3 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
	strings:
		$s0 = "Proxies destination address/port for TCP" fullword wide
		$s3 = "\\Device\\StreamPortal" fullword wide
		$s4 = "Transport-Data Proxy Sub-Layer" fullword wide
		$s5 = "Cookie: SN=" fullword ascii
		$s6 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
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
      score = 75
   strings:
      $e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
      $e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
      $e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
      $e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
      $e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase
   condition:
      (any of ($e*))
}

rule APT_Winnti_MAL_Dec19_2 {
   meta:
      description = "Detects Winnti malware"
      author = "Unknown"
      reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
      date = "2019-12-06"
      score = 75
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
   strings:
      $b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [0-2] [8] 8B ?? 50 41 B9 40 00 00 00 41 B8 00 10 00 00 }
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
