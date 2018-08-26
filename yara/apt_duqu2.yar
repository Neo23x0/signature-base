/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-02
	Identifier: Duqu2
*/

/* Rule Set ----------------------------------------------------------------- */

rule Duqu2_Sample1 {
	meta:
		description = "Detects malware - Duqu2 (cross-matches with IronTiger malware and Derusbi)"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
		hash2 = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
		hash3 = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
		hash4 = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "MSI.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and $x1 ) or ( all of them )
}

rule Duqu2_Sample2 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
		hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
		hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
		hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
		hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
		hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
	strings:
		$s1 = "=<=Q=W=a=g=p=v=|=" fullword ascii
		$s2 = ">#>(>.>3>=>]>d>p>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of ($s*)
}

rule Duqu2_Sample3 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
	strings:
		$s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and $s1 )
}

rule Duqu2_Sample4 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s2 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s4 = "ProcessUserAccounts" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) ) or ( all of them )
}
rule Duqu2_UAs {
	meta:
		description = "Detects Duqu2 Executable based on the specific UAs in the file"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
		hash2 = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
	strings:
		$x1 = "Mozilla/5.0 (Windows NT 6.1; U; ru; rv:5.0.1.6) Gecko/20110501 Firefox/5.0.1 Firefox/5.0.1" fullword wide
		$x2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7xs5D9rRDFpg2g" fullword wide
		$x3 = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; FDM; .NET CLR 1.1.4322)" fullword wide
		$x4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 800KB and all of them )
}
