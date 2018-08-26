/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-31
	Identifier: Transformed Strings
*/

/* Rule Set ----------------------------------------------------------------- */

rule Typical_Malware_String_Transforms {
	meta:
		description = "Detects typical strings in a reversed or otherwise modified form"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-07-31"
		score = 60
	strings:
		/* Executables */
		$e1 = "exe.tsohcvs" fullword ascii
		$e2 = "exe.ssasl" fullword ascii
		$e3 = "exe.rerolpxe" fullword ascii
		$e4 = "exe.erolpxei" fullword ascii
		$e5 = "exe.23lldnur" fullword ascii
		$e6 = "exe.dmc" fullword ascii
		$e7 = "exe.llikksat" fullword ascii

		/* Libraries */
		$l1 = "lld.23lenreK" fullword ascii
		$l2 = "lld.ESABLENREK" fullword ascii
		$l3 = "lld.esabtpyrc" fullword ascii
		$l4 = "lld.trcvsm" fullword ascii
		$l5 = "LLD.LLDTN" fullword ascii

		/* Imports */
		$i1 = "paeHssecorPteG" fullword ascii
		$i2 = "sserddAcorPteG" fullword ascii
		$i3 = "AyrarbiLdaoL" fullword ascii
		$i4 = "AssecorPetaerC" fullword ascii

		/* Registry */
		$r1 = "teSlortnoCtnerruC" fullword ascii
		$r2 = "nuR\\noisreVtnerruC" fullword ascii

		/* Folders */
		$f1 = "\\23metsys\\" ascii
		$f2 = "\\23metsyS\\" ascii
		$f3 = "niB.elcyceR$" fullword ascii
		$f4 = "%tooRmetsyS%" fullword ascii

		/* False Positives */
		$fp1 = "Application Impact Telemetry Static Analyzer" fullword wide
	condition:
		( uint16(0) == 0x5a4d and 1 of them and not 1 of ($fp*) )
}
