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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
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

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-12
   Identifier: Mirai
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_1_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
      hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
   strings:
      $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and all of them )
}

rule Miari_2_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
      $s2 = "GET /g.php HTTP/1.1" fullword ascii
      $s3 = "https://%[^/]/%s" fullword ascii
      $s4 = "pass\" value=\"[^\"]*\"" fullword ascii
      $s5 = "jbeupq84v7.2y.net" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them )
}

rule MAL_ELF_LNX_Mirai_Oct10_1 {
   meta:
      description = "Detects ELF Mirai variant"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
   strings:
      $x1 = " -r /vi/mips.bushido; "
      $x2 = "/bin/busybox chmod 777 * /tmp/" fullword ascii

      $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s2 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s3 = "POST /cdn-cgi/" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and (
         ( 1 of ($x*) and 1 of ($s*) ) or
         all of ($x*)
      )
}

rule MAL_ELF_LNX_Mirai_Oct10_2 {
   meta:
      description = "Detects ELF malware Mirai related"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
   strings:
      $c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and all of them
}
