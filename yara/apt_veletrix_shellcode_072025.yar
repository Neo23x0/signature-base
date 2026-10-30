rule apt_veletrix_shellcode_072025 {
    meta:
        author = "0x0d4y"
        description = "This rule detects intrinsic patterns of Veletrix Shellcode."
        date = "2025-07-07"
        score = 100
        reference = "https://0x0d4y.blog/telecommunications-supply-chain-china-nexus-threat-technical-analysis-of-veletrix-loaders-strategic-infrastructure-positioning/"
        yarahub_reference_md5 = "81f76f83d4c571fe95772f21aff4d0b9"
        yarahub_uuid = "1d4c08bc-0498-43bb-81f3-08477d81233e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "win.veletrix"

    strings:
        $decryption_2ndstage_algorithm = { 45 33 C0 85 C0 74 ?? 41 8D 0C 30 45 03 C6 80 34 39 ?? 44 3B C0 72 ?? 03 F0 8B D6 48 03 D7 }
        $ror13_alg = { 0F BE 01 C1 CA 0D 80 39 61 7C 03 83 C2 E0 03 D0 48 FF C1 49 83 EA 01 75 }

    condition:
        $decryption_2ndstage_algorithm and
        $ror13_alg
}