rule MAL_Gopuram_Apr23 {
    meta:
        description = "Detects Lazarus Gopuram malware"
        reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-04-04"
        hash = "beb775af5196f30e0ee021790a4978ca7a7ac2a7cf970a5a620ffeb89cc60b2c"
        hash = "97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"
        id = "e0bb43b0-542b-5c8e-bcba-0326f80efaa0"
    strings:
        // VTgrep content:"%s.TxR.0.regtrans-ms" hits only the 2 hashes above
        $path = "%s.TxR.0.regtrans-ms"
    condition:
        uint16(0) == 0x5A4D and $path and filesize < 10MB
}

