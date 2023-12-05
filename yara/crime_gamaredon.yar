rule MAL_SUSP_Gamaredon_GetImportByHash {
    meta:
        description = "Detects Gamaredon APIHashing"
        author = "Frank Boldewin (@r3c0nst)"
        date = "2021-05-12"
        reference  = "https://twitter.com/r3c0nst/status/1392405576131436546?s=20"
        hash1 = "2d03a301bae0e95a355acd464afc77fde88dd00232aad6c8580b365f97f67a79"
        hash2 = "43d6e56515cca476f7279c3f276bf848da4bc13fd15fad9663b9e044970253e8"
        hash3 = "5c09f6ebb7243994ddc466058d5dc9920a5fced5e843200b1f057bda087b8ba6"
        id = "8f28273e-e8ca-52cb-8dbc-a235598b1975"
    strings:
        $ParseImgExportDir = { 8B 50 3C 03 D0 8B 52 78 03 D0 8B 4A 1C 03 C8 }
        $djb2Hashing = { 8B 75 08 BA 05 15 00 00 8B C2 C1 E2 05 03 D0 33 DB 8A 1E 03 D3 46 33 DB 8A 1E 85 DB 75 } /* https://theartincode.stanis.me/008-djb2/ */
    condition:
        uint16(0) == 0x5a4d and all of them
}