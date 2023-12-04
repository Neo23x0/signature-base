/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-05-07
	Identifier: Kraken_Malware
*/

rule Kraken_Bot_Sample {
	meta:
		description = "Kraken Bot Sample - file inf.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
		date = "2015-05-07"
		hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"
		score = 90
	strings:
		$s2 = "%s=?getname" fullword ascii
		$s4 = "&COMPUTER=^" fullword ascii
		$s5 = "xJWFwcGRhdGElAA=" fullword ascii /* base64 encoded string '%appdata%' */
		$s8 = "JVdJTkRJUi" fullword ascii /* base64 encoded string '%WINDIR' */
		$s20 = "btcplug" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

