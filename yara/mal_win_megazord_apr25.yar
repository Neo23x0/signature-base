rule MAL_WIN_Megazord_Apr25 {
    meta:
        description = "This Yara rule from ISH Tecnologia's Heimdall Security Research Team, detects the main components of the Megazord Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-16"
        score = 80
        reference = "https://ish.com.br/wp-content/uploads/2025/04/A-Anatomia-do-Ransomware-Akira-e-sua-expansao-multiplataforma.pdf"
        hash = "FD380DB23531BB7BB610A7B32FC2A6D5"
        uuid = "6225a690-8f54-4a50-a19a-8f7523537228"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.akira"

    strings:
        $megazord_str_I = "powerranges" ascii
        $megazord_str_II = "onion" ascii
        $megazord_str_III = "powershell" ascii
        $megazord_str_IV = "megazord" ascii
        $megazord_str_V = "mal_public_key_bytes" ascii
        $megazord_str_VI = "runneradmin" ascii
        $megazord_str_VII = "//rustc" ascii


    condition:
        uint16(0) == 0x5a4d and
        6 of ($megazord_str_*)
}
