rule apt_win32_dll_rat_1a53b0cp32e46g0qio7
{
	meta:
		description = "Detects Inocnation Malware"
		author = "Fidelis Cybersecurity"
		score = 75
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
		reference = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
	strings:
		// Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0;rv:11.0) like Gecko
		$s1 = { c7 [2] 64 00 63 00 c7 [2] 69 00 62 00 c7 [2] 7a 00 7e 00 c7 [2] 2d 00 43 00 c7 [2] 59 00 2d 00 c7 [2] 3b 00 23 00 c7 [2] 3e 00 36 00 c7 [2] 2d 00 5a 00 c7 [2] 42 00 5a 00 c7 [2] 3b 00 39 00 c7 [2] 36 00 2d 00 c7 [2] 59 00 7f 00 c7 [2] 64 00 69 00 c7 [2] 68 00 63 00 c7 [2] 79 00 22 00 c7 [2] 3a 00 23 00 c7 [2] 3d 00 36 00 c7 [2] 2d 00 7f 00 c7 [2] 7b 00 37 00 c7 [2] 3c 00 3c 00 c7 [2] 23 00 3d 00 c7 [2] 24 00 2d 00 c7 [2] 61 00 64 00 c7 [2] 66 00 68 00 c7 [2] 2d 00 4a 00 c7 [2] 68 00 6e 00 c7 [2] 66 00 62 00 } // offset 10001566
		// Software\Microsoft\Windows\CurrentVersion\Run
		$s2 = { c7 [2] 23 00 24 00 c7 [2] 24 00 33 00 c7 [2] 38 00 22 00 c7 [2] 00 00 33 00 c7 [2] 24 00 25 00 c7 [2] 3f 00 39 00 c7 [2] 38 00 0a 00 c7 [2] 04 00 23 00 c7 [2] 38 00 00 00 c7 [2] 43 00 66 00 c7 [2] 6d 00 60 00 c7 [2] 67 00 52 00 c7 [2] 6e 00 63 00 c7 [2] 7b 00 67 00 c7 [2] 70 00 00 00 c7 [2] 43 00 4d 00 c7 [2] 44 00 00 00 c7 [2] 0f 00 43 00 c7 [2] 00 00 50 00 c7 [2] 49 00 4e 00 c7 [2] 47 00 00 00 c7 [2] 11 00 12 00 c7 [2] 17 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 11 00 06 00 c7 [2] 44 00 45 00 c7 [2] 4c 00 00 00 } // 10003D09
		$s3 = { 66 [4-7] 0d 40 83 f8 44 7c ?? }
		// xor		word ptr [ebp+eax*2+var_5C], 14h
		// inc		eax
		// cmp     	eax, 14h
		// Loop to decode a static string. It reveals the "1a53b0cp32e46g0qio9" static string sent in the beacon
		$s4 = { 66 [4-7] 14 40 83 f8 14 7c ?? } // 100017F0
		$s5 = { 66 [4-7] 56 40 83 f8 2d 7c ?? } // 10003621
		$s6 = { 66 [4-7] 20 40 83 f8 1a 7c ?? } // 10003640
		$s7 = { 80 [2-7] 2e 40 3d 50 02 00 00 72 ?? } //  10003930
		$s8 = "%08x%08x%08x%08x" wide ascii
		$s9 = "WinHttpGetIEProxyConfigForCurrentUser" wide ascii
	condition:
		(uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and (all of them)
}
