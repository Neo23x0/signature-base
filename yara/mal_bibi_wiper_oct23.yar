
rule MAL_LNX_BiBi_Linux_Wiper {
	meta:
		author ="Felipe Duarte, Security Joes"
		description ="Detects BiBi-Linux Wiper"
		hash ="23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"
		reference = "https://www.securityjoes.com/post/bibi-linux-a-new-wiper-dropped-by-pro-hamas-hacktivist-group"
		
	strings:
		$str1 = "[+] Stats: "
		$str2 = { 2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69 00 }
		$str3 = "[!] Waiting For Queue "
		$str4 = "[+] Round "
		$str5 = "[+] Path: "
		$str6 = "[+] CPU cores: " 
		$str7 = "Threads: "

	condition:
		all of them
}