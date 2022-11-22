import "pe"

rule HKTL_Nighthawk_RAT {
	meta:
		description = "Detects Nighthawk RAT"
		author="Frank Boldewin (@r3c0nst)"
		references = "https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
		hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		hash3 = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
		hash4 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"
		date="2022-22-11"

	strings:
		$pattern1 = { 48 8d 0d ?? ?? ?? ?? 51 5a 48 81 c1 ?? ?? ?? ?? 48 81 c2 ?? ?? ?? ?? ff e2 }
		$pattern2 = { 66 03 D2 66 33 D1 66 C1 E2 02 66 33 D1 66 23 D0 0F B7 C1 }

	condition:
		uint16(0) == 0x5A4D and filesize < 2MB and
		((1 of them) or
		(pe.section_index(".profile") and pe.section_index(".detourc")))
}