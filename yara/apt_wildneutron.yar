/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-07-10
	Identifier: WildNeutron
*/

/* Rule Set ----------------------------------------------------------------- */

rule WildNeutron_Sample_1 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "2b5065a3d0e0b8252a987ef5f29d9e1935c5863f5718b83440e68dc53c21fa94"
		id = "7bcb407f-7f01-540a-852c-a37456270888"
	strings:
		$s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s8 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
		$s9 = "Key Usage" fullword ascii /* score: '12.00' */
		$s32 = "UPDATE_ID" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00' */
		$s37 = "id-at-commonName" fullword ascii /* score: '8.00' */
		$s38 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
		$s39 = "RSA-alt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00' */
		$s40 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule WildNeutron_Sample_2 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "8d80f9ef55324212759f4b6070cb8fce18a008ae9dd8b9598553206654d13a6f"
		id = "1893c251-f81a-5361-91fa-f91a6d1379d2"
	strings:
		$s0 = "rundll32.exe \"%s\",#1" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s1 = "IgfxUpt.exe" fullword wide /* score: '20.00' */
		$s2 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s3 = "Intel(R) Common User Interface" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s11 = "Key Usage" fullword ascii /* score: '12.00' */
		$s12 = "Intel Integrated Graphics Updater" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00' */
		$s13 = "%sexpires on    : %04d-%02d-%02d %02d:%02d:%02d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule WildNeutron_Sample_3 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
		id = "1c5d1442-b2be-5a34-b5c9-78aaf67072c4"
	strings:
		$x1 = "178.162.197.9" fullword ascii /* score: '9.00' */
		$x2 = "\"http://fw.ddosprotected.eu:80 /opts resolv=drfx.chickenkiller.com\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */

		$s1 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s2 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s3 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s5 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
		$s6 = "ECDSA with SHA256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
		$s7 = "Acer LiveUpdater" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 2020KB and
		( 1 of ($x*) or all of ($s*) )
}

rule WildNeutron_Sample_4 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
		id = "52ff5770-1ca4-54d9-b69d-8af0c392084e"
	strings:
		$x1 = "WinRAT-Win32-Release.exe" fullword ascii /* score: '22.00' */

		$s0 = "rundll32.exe \"%s\",#1" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s1 = "RtlUpd.EXE" fullword wide /* score: '20.00' */
		$s2 = "RtlUpd.exe" fullword wide /* score: '20.00' */
		$s3 = "Driver Update and remove for Windows x64 or x86_32" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "Realtek HD Audio Update and remove driver Tool" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
		$s5 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s6 = "Key Usage" fullword ascii /* score: '12.00' */
		$s7 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 1240KB and all of them
}

rule WildNeutron_Sample_5 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
		id = "0df63255-155d-56b9-b86b-491855983095"
	strings:
		$s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s4 = "sha-1WithRSAEncryption" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s5 = "Postal code" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00' */
		$s6 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
		$s7 = "Key Usage" fullword ascii /* score: '12.00' */
		$s8 = "TLS-RSA-WITH-3DES-EDE-CBC-SHA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
		$s9 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule WildNeutron_Sample_6 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
		id = "c5d87cad-d1ca-5766-90c1-fc8ecfa3f14f"
	strings:
		$s0 = "mshtaex.exe" fullword wide /* score: '20.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 310KB and all of them
}

rule WildNeutron_Sample_7 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
		id = "22561c55-4294-50c9-a9b9-7b4ed98eec09"
	strings:
		$s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00' */
		$s1 = "PEM_read_bio_PrivateKey failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii /* score: '23.00' */
		$s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s4 = "clapi32.dll" fullword ascii /* score: '21.00' */
		$s5 = "Connection from %s port %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = "/usr/etc/ssh_known_hosts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00' */
		$s7 = "Version: %s - %s %s %s %s" fullword ascii /* score: '16.00' */
		$s8 = "[-] connect()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.00' */
		$s9 = "/bin/sh /usr/etc/sshrc" fullword ascii /* score: '12.42' */
		$s10 = "kexecdhs.c" fullword ascii /* score: '12.00' */
		$s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii /* score: '11.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

/* deatcivate because its less relevant
rule HKTL_NativeCmd_subTee_Jul15 {
   meta:
      description = "NativeCmd - used by various threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10"
      modified = "2023-01-06"
      old_rule_name = "subTee_nativecmd"
      score = 40
      hash = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
   strings:
      $x2 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii 
      $x3 = "Error executing CreateProcess()!!" fullword wide 
      $x4 = "cmdcmdline" fullword wide
      $x5 = "Invalid input handle!!!" fullword ascii
      $s5 = "Usage: destination [reference]" fullword wide
      $s6 = ".com;.exe;.bat;.cmd" wide
      $s15 = "%-8s %-3s  %*s %s  %s" fullword wide
      $s16 = " %%%c in (%s) do " fullword wide
   condition:
      uint16(0) == 0x5a4d and ( 2 of ($x*) or 6 of ($s*) )
}
*/

rule WildNeutron_Sample_9 {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10"
      modified = "2023-01-06"
      score = 60
      hash = "781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
      id = "dbfdbe8c-4a4a-5512-a03d-e9f80c853d48"
   strings:
      $s0 = "http://get.adobe.com/flashplayer/" wide  /* score: '30.00' */
      $s4 = " Player Installer/Uninstaller" fullword wide  /* score: '11.42' */
      $s5 = "Adobe Flash Plugin Updater" fullword wide  /* score: '11.00' */
      $s6 = "uSOFTWARE\\Adobe" fullword wide  /* score: '10.42' */
      $s11 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
      $s12 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
      $s13 = "%d -> %d" fullword wide /* score: '7.00' */
   condition:
      uint16(0) == 0x5a4d and filesize < 1477KB and all of them
}

rule WildNeutron_Sample_10 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"
		id = "5654a36f-8502-5e18-b8f3-94d4add466a7"
	strings:
		$n1 = "/c for /L %%i in (1,1,2) DO ping 127.0.0.1 -n 3 & type %%windir%%\\notepad.exe > %s & del /f %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '46.00' */

		$s1 = "%SYSTEMROOT%\\temp\\_dbg.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00' */
		$s2 = "%SYSTEMROOT%\\SysWOW64\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
		$s3 = "%SYSTEMROOT%\\System32\\dpcore16t.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
		$s4 = "%SYSTEMROOT%\\System32\\wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
		$s5 = "%SYSTEMROOT%\\System32\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
		$s6 = "%SYSTEMROOT%\\System32\\kernel32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s7 = "%SYSTEMROOT%\\SysWOW64\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
		$s8 = "%SYSTEMROOT%\\System32\\msvcse.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
		$s9 = "%SYSTEMROOT%\\System32\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
		$s10 = "%SYSTEMROOT%\\System32\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
		$s11 = "%SYSTEMROOT%\\SysWOW64\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */

		$x1 = "wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00' */
		$x2 = "dpcore16t.dll" fullword ascii /* score: '21.00' */
		$x3 = "mspool.dll" fullword ascii /* score: '21.00' */
		$x4 = "msvcse.exe" fullword ascii /* score: '20.00' */
		$x5 = "mshtaex.exe" fullword wide /* score: '20.00' */
		$x6 = "iastor32.exe" fullword ascii /* score: '20.00' */

		$y1 = "Installer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$y2 = "Info: Process %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00' */
		$y3 = "Error: GetFileTime %s 0x%x" fullword ascii /* score: '17.00' */
		$y4 = "Install succeeded" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
		$y5 = "Error: RegSetValueExA 0x%x" fullword ascii /* score: '9.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and
		(
			$n1 or ( 1 of ($s*) and 1 of ($x*) and 3 of ($y*) )
		)
}

/* Super Rules ------------------------------------------------------------- */


rule APT_MAL_WildNeutron_javacpl {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10"
      modified = "2023-01-06"
      old_rule_name = "WildNeutron_javacpl"
      score = 60
      hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
      hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
      hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
      id = "de82827e-61d4-559e-886a-78d5293ab141"
   strings:
      $s1 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" ascii fullword
      $s2 = "cmdcmdline" wide fullword
      $s3 = "\"%s\" /K %s" wide fullword
      $s4 = "Process is not running any more" wide fullword
      $s5 = "dpnxfsatz" wide fullword

      $op1 = { ff d6 50 ff 15 ?? ?? 43 00 8b f8 85 ff 74 34 83 64 24 0c 00 e8 ?? ?? 02 00 }
      $op2 = { b8 02 00 00 00 01 45 80 01 45 88 6a 00 47 52 89 7d 8c 03 d8 }
      $op3 = { 8b c7 f7 f6 46 89 b5 c8 fd ff ff 0f b7 c0 8b c8 0f af ce 3b cf }
   condition:
      uint16(0) == 0x5a4d and filesize < 5MB and (
         all of ($s*) or 
         all of ($op*)
      )
}
