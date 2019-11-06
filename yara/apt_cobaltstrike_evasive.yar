rule CobaltStrike_C2_Host_Indicator {
	meta:
		description = "Detects CobaltStrike C2 host artifacts"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_indicator_fp = "#Host: %s"
		$c2_indicator = "#Host:"
	condition:
		$c2_indicator and not $c2_indicator_fp
		and not uint32(0) == 0x0a786564
		and not uint32(0) == 0x0a796564
}

rule CobaltStrike_Sleep_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$sleep_decoder = {8B 07 8B 57 04 83 C7 08 85 C0 75 2C}
	condition:
		$sleep_decoder
}

rule CobaltStrike_C2_Encoded_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 encoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_enc_config = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? 69 6F 69 68 69 6B ?? ?? 69 6E 69 6A 68 69}
	condition:
		$c2_enc_config
}


rule CobaltStrike_C2_Decoded_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 decoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_dec_config = {01 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ??}
	condition:
		$c2_dec_config
}

rule CobaltStrike_Unmodifed_Beacon {
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"
	condition:
		all of them
}
