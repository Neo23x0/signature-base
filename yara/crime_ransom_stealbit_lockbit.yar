rule MAL_RANSOM_Stealbit_Aug21 {
	meta:
		description = "Detects Stealbit used by Lockbit 2.0 Ransomware Gang"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Lockbit2.Stealbit.yar"
		date = "2021-08-12"
		hash1 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
		hash2 = "bd14872dd9fdead89fc074fdc5832caea4ceac02983ec41f814278130b3f943e"
		id = "07b466cb-92b3-51f2-a702-2930bb7038c6"
	strings:
		$C2Decryption = {33 C9 8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 7C 72 E9 E8}
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and $C2Decryption
}