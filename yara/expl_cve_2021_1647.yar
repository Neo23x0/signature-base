/* minimal modifications by Florian Roth */
rule EXPL_CVE_2021_1647_Apr21_1 {
   meta:
        description = "Detects samples that exploit CVE-2021-1647"
        author = "Arkbird_SOLG"
        reference = "https://attackerkb.com/topics/DzXZpEuBeP/cve-2021-1647-microsoft-windows-defender-zero-day-vulnerability"
        date = "2021-05-04"
        hash1 = "6e1e9fa0334d8f1f5d0e3a160ba65441f0656d1f1c99f8a9f1ae4b1b1bf7d788"
        hash2 = "9eaea8a56c47524f6d6b2e2bb72d035c1aa782a4f069ef9df92a0af5c6ee612b"
        hash3 = "db0e53c9db41d4de21f4bbf1f60d977f5d935239d3fce8b902e8ef0082796cc7"
        hash4 = "24d9ff44affea06435829507e8e6cb4b659468aa2af510031ed963caf5a6d77a"
        id = "ecce018e-1bee-5374-b6c8-984c2a8c2530"
   strings:
        $seq1 = { 83 7d ec 01 0f 8e fe 76 ff ff 83 45 f4 01 83 7d f4 01 0f 8e e4 76 ff ff 8b 45 e4 89 04 24 e8 12 74 ff ff 83 ec 04 a1 [2] 01 b1 85 c0 75 0e 8b 45 e4 89 04 24 e8 fb 73 ff ff 83 ec 04 a1 28 ?? 01 b1 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff d0 83 ec 08 b8 00 00 00 00 c9 c2 04 00 55 89 e5 83 ec 10 c7 45 f4 00 ?? 01 70 8b 45 08 83 e8 01 a3 70 ?? 01 b1 c7 05 74 ?? 01 b1 00 00 00 00 c7 05 a0 ?? 02 b1 00 00 00 00 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 }
        $seq2 = { a1 74 ?? 01 b1 83 e8 01 83 e0 01 85 c0 74 0e 8b 15 5c ?? 01 b1 8b 45 f4 01 d0 89 45 fc 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 83 7d 0c 00 74 1d a1 74 ?? 01 b1 83 e8 01 83 e0 01 85 c0 74 0e 8b 15 5c ?? 01 b1 8b 45 f4 01 d0 89 45 fc 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 83 7d 0c 00 74 1d a1 74 ?? 01 b1 83 e8 01 83 e0 01 85 c0 74 0e 8b 15 5c ?? 01 b1 8b 45 f4 01 d0 89 45 fc 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 83 e0 fe 89 c2 a1 [2] 01 b1 29 c2 89 d0 25 ff 0f 00 00 a3 5c ?? 01 b1 a1 74 ?? 01 b1 a3 a0 ?? 02 b1 8b 15 70 ?? 01 b1 a1 74 ?? 01 b1 01 d0 d1 e8 83 c0 01 a3 74 ?? 01 b1 83 7d 0c 00 75 0e 8b 15 5c ?? 01 b1 8b 45 f4 01 d0 89 45 fc c7 45 f8 00 00 00 00 eb 19 8b 45 f8 05 e2 ff ff 7f 8d 14 00 8b 45 fc 01 d0 66 c7 00 01 00 83 45 f8 01 83 7d f8 3b 7e e1 8b 45 fc }
   condition:
     filesize > 10KB and filesize < 10000KB and all of them
}