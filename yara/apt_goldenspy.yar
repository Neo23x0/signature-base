rule APT_MAL_BKA_GoldenSpy_Aug20_1 {
	meta:
		description = "Detects variants of GoldenSpy Malware"
        reference = "https://www.bka.de/SharedDocs/Kurzmeldungen/DE/Warnhinweise/200821_Cyberspionage.html"
        author = "BKA"
        date = "2020-08-21"
		id = "4f47087e-6e68-53ff-9446-72a1751da359"
	strings:
		$str01 = {c78510ffffff00000000 c78514ffffff0f000000 c68500ffffff00 c78528ffffff00000000 c7852cffffff0f000000 c68518ffffff00 c78540ffffff00000000 c78544ffffff0f000000 c68530ffffff00 c645fc14 80bd04feffff00}
		$str02 = "Ryeol HTTP Client Class" ascii
		$str03 = "----RYEOL-FB3B405B7EAE495aB0C0295C54D4E096-" ascii
		$str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fwkp.exe" ascii
		$str05 = "svmm" ascii
		$str06 = "PROTOCOL_" ascii
		$str07 = "softList" ascii
		$str08 = "excuteExe" ascii
	condition:
	 	uint16(0) == 0x5A4D and 5 of ($str*)
}

