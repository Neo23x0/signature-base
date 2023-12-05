rule MAL_CRIME_suspicious_hex_string_Jun21_1 : CRIME PE {
    meta:
        author = "Nils Kuhnert"
        date = "2021-06-04"
        description = "Triggers on parts of a big hex string available in lots of crime'ish PE files."
        hash1 = "37d60eb2daea90a9ba275e16115848c95e6ad87d20e4a94ab21bd5c5875a0a34"
        hash2 = "3380c8c56d1216fe112cbc8f1d329b59e2cd2944575fe403df5e5108ca21fc69"
        hash3 = "cd283d89b1b5e9d2875987025009b5cf6b137e3441d06712f49e22e963e39888"
        hash4 = "404efa6fb5a24cd8f1e88e71a1d89da0aca395f82d8251e7fe7df625cd8e80aa"
        hash5 = "479bf3fb8cff50a5de3d3742ab4b485b563b8faf171583b1015f80522ff4853e"
        id = "2ad208fa-c7a5-5df9-96fe-4a84dc770f0f"
    strings:
        $a1 = "07032114130C0812141104170C0412147F6A6A0C041F321104130C0412141104030C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141122130C0412146423272A711221112B1C042734170408622513143D20262B0F323038692B312003271C170B3A2F286623340610241F001729210579223202642200087C071C17742417020620141462060F12141104130C0412141214001C0412011100160C0C002D2412130C0412141104130C04121A11041324001F140122130C0134171" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and all of them
}

rule MAL_CRIME_Unknown_LNK_Jun21_1: LNK POWERSHELL {
    meta:
        author = "Nils Kuhnert"
        date = "2021-06-04"
        description = "Triggers on malicious link files which calls powershell with an obfuscated payload and downloads an HTA file."
        hash1 = "8fc7f25da954adcb8f91d5b0e1967e4a90ca132b280aa6ae73e150b55d301942"
        hash2 = "f5da192f4e4dfb6b728aee1821d10bec6d68fb21266ce32b688e8cae7898a522"
        hash3 = "183a9b3c04d16a1822c788d7a6e78943790ee2cdeea12a38e540281091316e45"
        hash4 = "a38c6aa3e1c429a27226519b38f39f03b0b1b9d75fd43cd7e067c5e542967afe"
        hash5 = "455f7b6b975fb8f7afc6295ec40dae5696f5063d1651f3b2477f10976a3b67b2"
        id = "d1aac420-fd91-5577-8efd-fcdd7f733981"
    strings:
        $uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide
    condition:
        uint16(0) == 0x004c and all of them
}

rule MAL_CRIME_Unknown_ISO_Jun21_1 : ISO POWERSHELL LNK {
    meta:
        author = "Nils Kuhnert"
        date = "2021-06-04"
        description = "Triggers on ISO files that mimick NOBELIUM TTPs, but uses LNK files that call powershell instead."
        hash1 = "425dbed047dd2ce760d0848ebf7ad04b1ca360f111d557fc7bf657ae89f86d36"
        hash2 = "f6944b6bca627e219d9c5065f214f95eb2226897a3b823b645d0fd78c281b149"
        hash3 = "14d70a8bdd64e9a936c2dc9caa6d4506794505e0e3870e3a25d9d59bcafb046e"
        hash4 = "9b2ca8eb6db34b07647a74171a5ff4c0a2ca8000da9876ed2db6361958c5c080"
        id = "73a1fc44-45c4-5253-b81d-fa6686dc0644"
    strings:
        $uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide
        $magic = "CD001" ascii
    condition:
        filesize < 5MB and all of them
}
