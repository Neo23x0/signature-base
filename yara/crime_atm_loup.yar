/* slightly modified by Florian Roth - removed the nocase statements for lower memory usage */

rule ATM_Malware_Loup {
	meta:
		description = "Detects ATM Malware Loup"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1295275546780327936"
		date = "2020-08-17"
		hash = "6c9e9f78963ab3e7acb43826906af22571250dc025f9e7116e0201b805dc1196"
		
		id = "2215a93f-d854-5f9b-b5cd-53962c45db08"
	strings:
		$String1 = "C:\\Users\\muham\\source\\repos\\loup\\Debug\\loup.pdb" ascii /* nocase */
		$String2 = "CurrencyDispenser1" ascii /* nocase */
		$Code = {50 68 C0 D4 01 00 8D 4D E8 51 68 2E 01 00 00 0F B7 55 08 52 E8} // Dispense
		
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and all of ($String*) and $Code
}