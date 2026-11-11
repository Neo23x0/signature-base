rule apt_veletrix_loader_072025 {
  meta:
      author = "0x0d4y"
      description = "This rule detects intrinsic patterns of Veletrix Loader."
      date = "2025-07-07"
      score = 100
      reference = "https://0x0d4y.blog/telecommunications-supply-chain-china-nexus-threat-technical-analysis-of-veletrix-loaders-strategic-infrastructure-positioning/"
      yarahub_reference_md5 = "81f76f83d4c571fe95772f21aff4d0b9"
      yarahub_uuid = "b8554d55-8563-4a5e-9e12-294cdbb9b593"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malware_family = "win.veletrix"

    strings:
    $decryption_shellcode_algorithm = { 8B 57 08 48 8B C8 41 FF D5 E8 ?? ?? ?? ?? 48 8B 4F 08 33 D2 48 FF C1 48 98 48 F7 F1 89 57 04 66 0F 1F 84 00 00 00 00 00 48 63 C3 F0 80 34 30 ?? FF C3 81 FB 73 05 00 00 72 ?? 8B 47 04 4C 8B C6 48 03 47 10 BA 74 05 00 00 4C 2B C0 [0-16] 41 0F B6 0C 00 88 08 }

    condition:
        uint16(0) == 0x5a4d and
        $decryption_shellcode_algorithm
}