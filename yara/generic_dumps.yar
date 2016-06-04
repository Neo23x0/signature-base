/* Disabled due to Benjamin Delphys sig overlap
rule LSASS_memory_dump_file {
	meta:
		description = "Detects a LSASS memory dump file"
		author = "Florian Roth"
		date = "2015/03/31"
		memory = 0
		score = 50
	strings:
		$s1 = "lsass.exe" ascii fullword
		$s2 = "wdigest.DLL" wide nocase
	condition:
        uint32(0) == 0x504D444D and all of them
} */

rule NTLM_Dump_Output {
	meta:
		description = "NTML Hash Dump output file - John/LC format"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
	strings:
		$s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
		$s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
	condition:
		1 of them
}
