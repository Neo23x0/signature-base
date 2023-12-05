
rule ATM_Malware_XFSCashNCR {
	meta:
		description = "Detects ATM Malware XFSCashNCR"
		author = "Frank Boldewin (@r3c0nst), modified by Florian Roth"
		reference = "https://twitter.com/r3c0nst/status/1166773324548063232"
		date = "2019-08-28"
		hash1 = "d6dff67a6b4423b5721908bdcc668951f33b3c214e318051c96e8c158e8931c0"

		id = "0a70ef9a-9dde-54c9-a3a2-dfceff32932b"
	strings:
		$Code1 = {50 8b 4d e8 8b 51 10 52 6a 00 68 2d 01 00 00 8b 45 e8 0f b7 48 1c 51 e8} // CDM Status
		$Code2 = {52 8d 45 d0 50 68 2e 01 00 00 8b 4d e8 0f b7 51 1c 52 e8} // Dispense
		$x_StatusMessage1 = "[+] Ingrese Denominacion ISO" nocase ascii
		$x_StatusMessage2 = "[+] Ingrese numero de billetes" nocase ascii
		$x_StatusMessage3 = "[!] FAIL.. dispensadores no encontrados" nocase ascii
		$x_StatusMessage4 = "[!] Unable continue, IMPOSIBLE abrir dispenser" nocase ascii
		$x_PDB = "C:\\Users\\cyttek\\Downloads\\xfs_cashXP\\Debug\\xfs_cash_ncr.pdb" nocase ascii
		$LogFile = "XfsLog.txt" nocase ascii

	condition:
		uint16(0) == 0x5A4D and filesize < 1500KB and ( 1 of ($x*) or 2 of them )
}
