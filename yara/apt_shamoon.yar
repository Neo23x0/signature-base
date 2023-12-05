rule CrowdStrike_Shamoon_DroppedFile { 
	meta:
		description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
		reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"
		id = "b350f1b1-db73-574b-957b-34e5a84f68b0"
	strings:
		$testn123 = "test123" wide
		$testn456 = "test456" wide
		$testn789 = "test789" wide
		$testdomain = "testdomain.com" wide $pingcmd = "ping -n 30 127.0.0.1 >nul" wide
	condition:
		(any of ($testn*) or $pingcmd) and $testdomain
}
