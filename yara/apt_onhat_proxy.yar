/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-12
	Identifier: ONHAT
*/

rule ONHAT_Proxy_Hacktool {
	meta:
		description = "Detects ONHAT Proxy - Htran like SOCKS hack tool used by Chinese APT groups"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 100
		hash1 = "30b2de0a802a65b4db3a14593126301e6949c1249e68056158b2cc74798bac97"
		hash2 = "94bda24559713c7b8be91368c5016fc7679121fea5d565d3d11b2bb5d5529340"
		hash3 = "a26e75fec3b9f7d5a1c3d0ce1e89e4b0befb7a601da0c69a4cf96301921771dd"
		hash4 = "c202e9d5b99f6137c7c07305c7314e55f52bae832d460c44efc8f2a90ff03615"
		hash5 = "dded62ad85c0bdd68bcc96f88d8ba42d5ad0ef999911ebdea3f561a4491ebbc6"
		hash6 = "f0954774c91603fc2595f0ba0727b9af4e80f6f9be7bb629e7fb6ba4309ed4ea"
		hash7 = "f3906be01d51e2e1ae9b03cd09702b6e0794b9c9fd7dc04024f897e96bb13232"
		hash8 = "f65ae9ccf988a06a152f27a4c0d7992100a2d9d23d80efe8d8c2a5c9bd78a3a7"
	strings:
		$s1 = "INVALID PARAMETERS. TYPE ONHAT.EXE -h FOR HELP INFORMATION." fullword ascii
		$s2 = "[ONHAT] LISTENS (S, %d.%d.%d.%d, %d) ERROR." fullword ascii
		$s3 = "[ONHAT] CONNECTS (T, %d.%d.%d.%d, %d.%d.%d.%d, %d) ERROR." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and ( 1 of ($s*) ) ) or ( 2 of them )
}
