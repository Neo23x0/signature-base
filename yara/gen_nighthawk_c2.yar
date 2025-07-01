import "pe"

rule EXT_HKTL_Nighthawk_RAT
{
	meta:
		description = "Detects Nighthawk RAT"
		author = "Frank Boldewin (@r3c0nst)"
		references = "https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
		hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		hash3 = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
		hash4 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"
		hash5 = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"
		modified = "2025-07-01"
		date = "2022-11-22"

		id = "7a58b8bf-fb14-5758-bc2a-ad2c6fff1216"
	strings:
		$pattern1 = { 48 8d 0d ?? ?? ?? ?? 51 5a 48 81 c1 ?? ?? ?? ?? 48 81 c2 ?? ?? ?? ?? ff e2 }
		$pattern2 = { 66 03 D2 66 33 D1 66 C1 E2 02 66 33 D1 66 23 D0 0F B7 C1 }
		$pattern3 = { FF 7F 48 3B F0 48 0F 47 F0 48 8D }
		$pattern4 = { 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA 0F 05 C3 }
		$pattern5 = { 48 B8 AA AA AA AA AA AA AA 02 48 ?? ?? ?? ?? 0F 84 }
		$pattern6 = { 65 48 8B 04 25 30 00 00 00 48 8B 80 }

	condition:
		uint16(0) == 0x5A4D and filesize < 2MB and
		(3 of ($pattern*) or
		(pe.section_index(".profile") >= 0 and pe.section_index(".detourc") >= 0 and pe.section_index(".detourd") >= 0))
}

rule HKTL_MAL_Nighthawk_Nov_2022_1 : nighthawk beacon {
   meta:
        description = "Detect the Nighthawk dropped beacon"
        author = "Arkbird_SOLG"
        reference = "https://web.archive.org/web/20221125224850/https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
        date = "2022-11-22"
        hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
        hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
        hash3 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"
        score = 75
        id = "a46d5034-e8e3-5c30-90d9-ea97b8384341"
   strings:
        $s1 = { 44 8b ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d c0 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d 20 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d 00 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d e0 e8 [2] ff ff 33 d2 e9 ee 04 00 00 48 8d 44 24 68 48 89 44 24 20 41 b9 01 00 00 00 45 33 c0 48 8d 95 a0 00 00 00 ff 15 [2] 09 00 85 c0 0f 85 74 04 00 00 48 89 7c 24 28 48 89 7c 24 20 45 33 c9 45 33 c0 48 8d 15 [2] 0a 00 48 8b 4c 24 68 ff 15 [2] 09 00 85 }
        $s2 = { 4d 85 c0 0f 84 83 00 00 00 49 21 18 33 d2 44 8d 43 01 33 c9 ff 15 [2] 08 00 48 8b f0 48 85 c0 74 6a 44 8d 43 04 48 8b d5 48 8b c8 ff 15 [2] 08 00 48 8b e8 48 85 c0 74 49 48 8d 44 24 70 33 d2 44 8d 4b 24 48 89 44 24 20 4c 8d 44 24 30 48 8b cd ff 15 [2] 08 00 8b }
        $s3 = { 48 85 c0 0f 84 [2] 00 00 4d 8b cc 49 83 7c 24 18 08 72 04 4d 8b 0c 24 4d 8b c5 49 83 7d 18 08 72 04 4d 8b 45 00 49 8b ?? 49 83 ?? 18 08 72 03 49 8b }
        $s4 = { 44 8b 44 24 44 4c 89 [2-3] 89 95 00 02 00 00 2b c7 8b d7 49 03 d0 48 03 d1 4c 8d 8d 00 02 00 00 44 8b c0 49 8b cf ff 15 [2] 04 00 33 d2 85 c0 0f 84 [2] ff ff 03 bd 00 02 00 00 8b 44 24 40 3b f8 48 8b 4d ?? 4c 8b }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
