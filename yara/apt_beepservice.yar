/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-12
	Identifier:
*/

/* Rule Set ----------------------------------------------------------------- */

rule BeepService_Hacktool {
	meta:
		description = "Detects BeepService Hacktool used by Chinese APT groups"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 85
		hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
		hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
		hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
		hash4 = "6db2ffe7ec365058f9d3b48dcca509507c138f19ade1adb5f13cf43ea0623813"
	strings:
		$x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii

		$s1 = "123.exe" fullword ascii
		$s2 = "regclean.exe" fullword ascii
		$s3 = "192.168.88.69" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $x1 and 1 of ($s*)
}
