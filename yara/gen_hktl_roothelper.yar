
rule EXT_SUSP_OBFUSC_macOS_RootHelper_Obfuscated {
	meta:
		author = "im0prtp3"
		description = "Yara for the public tool 'roothelper'. Used by XCSSET (https://gist.github.com/NullArray/f39b026b9e0d19f1e17390a244d679ec)"
		reference = "https://twitter.com/imp0rtp3/status/1401912205621202944"
		date = "2021-06-07"
		score = 65
		id = "7ff91c00-8178-525c-bb41-d09cf7cda588"
	strings:
		$a1 = "E: neither argv[0] nor $_ works." fullword
		
		// Debug Strings - only available when compiled as debug 
		$b1 = "shll=%s\n" fullword
		$b2 = "argv[%d]=%.60s\n" fullword
		$b3 = "getenv(%s)=%s\n" fullword
		$b4 = "argc=%d\n" fullword
		$b5 = "argv=<null>\n" fullword
		
		$c1 = "%s%s%s: %s\n" fullword
		$c2 = "x%lx" fullword
		$c3 = "=%lu %d" fullword
		$c4 = "%lu %d%c" fullword
		
		// Function names
		$f1 = "rmarg"
		$f2 = "chkenv"
		$f3 = "untraceable"
		$f4 = "arc4"
		/* $f5 = "xsh" fullword */
		$f6 = "stte"
		$f7 = "with_file"

		// "key" function
		$opcodes_1 = { 99 F7 7D ?? 4C 63 C2 42 0F B6 14 01 0F B6 3D } 
		// "stte" function
		$opcodes_2 = { C6 [3] 00 00 00 C6 [3] 00 00 00 C6 [3] 00 00 00 8A 05 [2] 00 00 0F B6 [3] 00 00 89 CA } 
		// "chkenv" function
		$opcodes_3 = { E8 [2] FF FF	8B 85 ?? F? FF FF 2B 85 ?? F? FF FF	83 ?? 01 89 85 ?? F? FF FF E9 ?? 00 00 00 } 

		// "rmarg" function
		$weak_opcodes_1 = {48 8B 45 ?? 48 8B 00 48 3B 45 ??	0F 95 C1 88 4D ??} 
		$weak_opcodes_2 = {	48 8B 45 ??	48 83 38 ??	0F 95 C1 88 4D ?? } // rmarg

	condition:
		( uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca ) and (
			$a1 or 
			3 of ($b*) or 
			5 of ($f*) or 
			all of ($opcodes*) or 
			( 2 of ($b*) and ( 2 of ($c*) or 2 of ($opcodes*) ) ) or
			( 3 of ($c*) and 4 of ($f*) ) or
			( 2 of ($opcodes*) and ( all of ($weak_opcodes*) or 3 of ($c*) ) )
		)
}
