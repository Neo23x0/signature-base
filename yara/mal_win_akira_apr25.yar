rule MAL_WIN_Akira_Apr25 {
    meta:
        description = "This Yara rule from ISH Tecnologia's Heimdall Security Research Team detects key components of Akira Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-11"
        score = 90
        reference = "https://ish.com.br/wp-content/uploads/2025/04/A-Anatomia-do-Ransomware-Akira-e-sua-expansao-multiplataforma.pdf"
        hash = "205589629EAD5D3C1D9E914B49C08589"
        uuid = "76722cb6-70be-465f-9ef1-afd78f694289"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.akira"

    strings:
        $code_custom_algorithm = { 44 8B CF 90 42 0F B6 4C 0D ?? 83 E9 4E 44 8D 04 89 45 03 C0 B8 09 04 02 81 41 F7 E8 41 03 D0 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 44 2B C0 41 83 C0 7F B8 09 04 02 81 41 F7 E8 41 03 D0 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 44 2B C0 46 88 44 0D ?? 49 FF C1 }
        $code_aes_key_expansion = { 41 8D 41 FF 33 D2 8B 0C ?? 41 8B C1 41 F7 F2 85 D2 75 ?? 44 8B C1 0F B6 C1 0F B6 0C ?? 41 8B C0 48 C1 E8 ?? C1 E1 ?? 0F B6 04 ?? 0B C8 41 8B C0 48 C1 E8 ?? C1 E1 ?? 0F B6 D0 49 C1 E8 ?? 0F B6 04 ?? 0B C8 41 0F B6 C0 C1 E1 ?? 0F B6 14 ?? 0F B6 45 00 0B CA 33 C8 48 FF C5 }
        $akira_str_I = "akira" ascii
        $akira_str_II = "onion" ascii
        $akira_str_III = "powershell" ascii
        $akira_str_IV = "akira_readme.txt" ascii


    condition:
        uint16(0) == 0x5a4d and
        all of ($code_*) and
        all of ($akira_str_*)
}
