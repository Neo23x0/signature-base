/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-10-04
	Identifier: Mirai
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_Botnet_Malware {
	meta:
		description = "Detects Mirai Botnet Malware"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-10-04"
		hash1 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash2 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash3 = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
		hash4 = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
		hash5 = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
		hash6 = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
		hash7 = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
		hash8 = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
		hash9 = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
		hash10 = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
		hash11 = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
		hash12 = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
		hash13 = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"
	strings:
		$x1 = "POST /cdn-cgi/" fullword ascii
		$x2 = "/dev/misc/watchdog" fullword ascii
		$x3 = "/dev/watchdog" ascii
		$x4 = "\\POST /cdn-cgi/" fullword ascii
		$x5 = ".mdebug.abi32" fullword ascii

		$s1 = "LCOGQGPTGP" fullword ascii
		$s2 = "QUKLEKLUKVJOG" fullword ascii
		$s3 = "CFOKLKQVPCVMP" fullword ascii
		$s4 = "QWRGPTKQMP" fullword ascii
		$s5 = "HWCLVGAJ" fullword ascii
		$s6 = "NKQVGLKLE" fullword ascii
	condition:
		uint16(0) == 0x457f and filesize < 200KB and
		(
			( 1 of ($x*) and 1 of ($s*) ) or
			4 of ($s*)
		)
}
