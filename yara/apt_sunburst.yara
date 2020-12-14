import "pe"

rule HKTL_NET_GUID_Sunburst {
    meta:
		description = "Detects typelibguid from Sunburst/Solarwinds attackers"
        reference = "https://www.virustotal.com/gui/file/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/details"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-14"
    strings:
        $typelibguid = "14e64ecd-0839-4fb5-a727-69a46cce6181" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

