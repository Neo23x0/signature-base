rule MAL_Prolock_Malware {
	meta:
		description = "Detects Prolock malware in encrypted and decrypted mode"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Prolock.Malware.yar"
		date = "2020-05-17"
		hash1 = "a6ded68af5a6e5cc8c1adee029347ec72da3b10a439d98f79f4b15801abd7af0"
		hash2 = "dfbd62a3d1b239601e17a5533e5cef53036647901f3fb72be76d92063e279178"
		
		id = "269bf0c5-8315-5405-8e44-e2cc5507a36a"
	strings:
		$DecryptionRoutine = {01 C2 31 DB B8 ?? ?? ?? ?? 31 04 1A 81 3C 1A}
		$DecryptedString1 = "support981723721@protonmail.com" nocase ascii
		$DecryptedString2 = "Your files have been encrypted by ProLock Ransomware" nocase ascii
		$DecryptedString3 = "msaoyrayohnp32tcgwcanhjouetb5k54aekgnwg7dcvtgtecpumrxpqd.onion" nocase ascii
		$CryptoCode = {B8 63 51 E1 B7 31 D2 8D BE ?? ?? ?? ?? B9 63 51 E1 B7 81 C1 B9 79 37 9E}
		
	condition:
		((uint16(0) == 0x5A4D) or (uint16(0) == 0x4D42)) and filesize < 100KB and (($DecryptionRoutine) or (1 of ($DecryptedString*) and $CryptoCode))
}