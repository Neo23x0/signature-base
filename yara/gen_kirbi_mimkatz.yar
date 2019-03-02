/*
	Yara Rule Set
	Author: Didier Stevens
	Date: 2016-08-13
	Identifier: KiRBi ticket for mimikatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
	condition:
		uint16(0) == 0x8276 and $asn1 at 0
}
