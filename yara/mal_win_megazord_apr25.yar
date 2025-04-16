rule MAL_WIN_Megazord_Apr25 {
    meta:
        description = "This Yara rule from ISH Tecnologia's Heimdall Security Research Team, detects the main components of the Megazord Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-11"
        score = 80
        reference = "https://ish.com.br/wp-content/uploads/2025/04/A-Anatomia-do-Ransomware-Akira-e-sua-expansao-multiplataforma.pdf"
        hash = "FD380DB23531BB7BB610A7B32FC2A6D5"
        uuid = "6225a690-8f54-4a50-a19a-8f7523537228"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.akira"

    strings:
        $code_custom_algorithm = { 89 c1 45 31 e6 31 e8 44 31 f0 35 ?? ?? ?? ?? c1 c0 0b 44 31 ff 44 31 ef 31 c7 81 f7 ?? ?? ?? ?? c1 c7 0b 44 31 e3 31 cb 31 fb 81 f3 ?? ?? ?? ?? c1 c3 0b 89 da 31 c2 89 84 24 ?? ?? ?? ?? 44 31 ed 31 d5 89 94 24 ?? ?? ?? ?? 81 f5 ?? ?? ?? ?? c1 c5 0b 41 89 e8 41 31 f8 89 bc 24 ?? ?? ?? ?? 41 31 cf 45 31 c7 44 89 84 24 ?? ?? ?? ?? 41 81 f7 ?? ?? ?? ?? 41 c1 c7 0b 41 31 d4 45 31 fc 41 81 f4 ?? ?? ?? ?? 41 c1 c4 0b 45 31 c5 45 31 e5 41 81 f5 ?? ?? ?? ?? 41 c1 c5 0b 89 9c 24 ?? ?? ?? ?? 31 d9 44 31 f9 44 31 e9 81 f1 ?? ?? ?? ?? c1 c1 0b 41 89 c8 45 31 e0 44 89 a4 24 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 31 e8 44 31 c0 35 ?? ?? ?? ?? c1 c0 0b 44 89 fa 44 89 bc 24 ?? ?? ?? ?? 31 fa 44 31 ea 31 c2 41 89 c1 81 f2 ?? ?? ?? ?? c1 c2 0b 41 31 d8 41 31 d0 41 81 f0 ?? ?? ?? ?? 41 c1 c0 0b 44 89 e8 44 89 ac 24 ?? ?? ?? ?? 31 e8 44 31 c8 44 31 c0 45 89 c3 35 }
        $megazord_str_I = "powerranges" ascii
        $megazord_str_II = "onion" ascii
        $megazord_str_III = "powershell" ascii
        $megazord_str_IV = "taskkill" ascii
        $megazord_str_V = "mal_public_key_bytes" ascii
        $megazord_str_VI = "runneradmin" ascii
        $megazord_str_VII = "//rustc" ascii


    condition:
        uint16(0) == 0x5a4d and
        $code_custom_algorithm and
        5 of ($megazord_str_*)
}
