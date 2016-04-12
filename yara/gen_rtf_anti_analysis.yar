rule RTF_Anti_Analysis_Header {
	meta:
		description = "Detects a malformed RTF document header - Anti-Analysis tricks"
		author = "Florian Roth"
		reference = "http://decalage.info/rtf_tricks"
		date = "2016-04-12"
      score = 70
	condition:
		uint32(0) == 0x74725C7B /* {\rt */
      and not uint8(4) == 0x66 /* nof followed by 'f' */
}

rule RTF_Anti_Analysis_Content {
	meta:
		description = "Detects a malformed RTF document header - Anti-Analysis tricks"
		author = "Florian Roth"
		reference = "http://decalage.info/rtf_tricks"
		date = "2016-04-12"
      score = 50
   strings:
      $r1 = /[\x0d\x0aa-f0-9\s]{64}(\{\\object\}|\\bin)[\x0d\x0aa-f0-9\s]{64}/ nocase
	condition:
		uint32(0) == 0x74725C7B /* {\rt */
      and $r1
}
