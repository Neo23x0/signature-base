rule CobaltStrike_C2_Indicator {
	meta:
		description = "Detects CobaltStrike C2 profile artifacts"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_indicator_fp = "#Host: %s"
        $c2_indicator = "#Host:"
    condition:
        $c2_indicator and not $c2_indicator_fp
}

rule CobaltStrike_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
	    $sleep_decoder = {8B 07 8B 57 04 83 C7 08 85 C0 75 2C}
    condition:
        $sleep_decoder
}