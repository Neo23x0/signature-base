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
        description        = "KiRBi ticket for mimikatz"
        author            = "Benjamin DELPY (gentilkiwi); Didier Stevens"

        id = "a37249e0-ab3b-50c2-9473-1e69185713cc"
    strings:
        $asn1            = { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
        $asn1_84        = { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

    condition:
        $asn1 at 0 or $asn1_84 at 0
}
