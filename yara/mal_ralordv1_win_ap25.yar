rule MAL_WIN_Ralordv1_Apr25 {
    meta:
        description = "This ISH Tecnologia Yara rule, detects the main components of the first version of RALord Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-01"
        score = 80
        reference = "https://ish.com.br/wp-content/uploads/2025/04/RALord-Novo-grupo-de-Ransomware-as-a-Service-1.pdf"
        hash = "BE15F62D14D1CBE2AECCE8396F4C6289"
        uuid = "67254633-3597-4770-9806-8b2e26c8f66a"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.ralord"

    strings:
        $code_pattern_quarterround = { 4? 31 ?? 48 8b ?? ?? ?? 4? 31 ?? 48 8b ?? ?? ?? 31 e8 4? 31 ?? 41 c1 ?? 0c c1 ?? 0c c1 ?? 0c 48 89 c2 c1 ?? 0c }
        $code_pattern_custom_alg = { 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 48 83 c0 08 48 3d 8? }
        $ralord_str_I = "chacha" ascii
        $ralord_str_II = "scorp" ascii
        $ralord_str_III = "RALord" ascii
        $ralord_str_IV = "onion" ascii
        $ralord_str_V = "/rust" ascii
        $ralord_str_VI = "BCryptGenRandom" ascii

    condition:
        uint16(0) == 0x5a4d and
        all of ($code_pattern_*) and
        4 of ($ralord_str_*)
}
