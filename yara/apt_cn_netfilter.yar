
/* slightly modified to detect only samples with a size upt to 1 MB */

rule MAL_Netfilter_Dropper_Jun_2021_1 {
   meta:
        description = "Detects the dropper of Netfilter rootkit"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1405483373280235520"
        date = "2020-06-18"
        hash1 = "a5c873085f36f69f29bb8895eb199d42ce86b16da62c56680917149b97e6dac"
        hash2 = "659e0d1b2405cadfa560fe648cbf6866720dd40bb6f4081d3dce2dffe20595d9"
        hash3 = "d0a03a8905c4f695843bc4e9f2dd062b8fd7b0b00103236b5187ff3730750540"
        tlp = "White"
        adversary = "Chinese APT Group"
        id = "d91f48aa-9580-572d-a72c-19b80624cdbe"
   strings:
        $seq1 = { b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fe ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 00 00 88 85 dc fd ff ff b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fd ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 50 00 50 e8 ?? 0d 00 00 83 c4 04 89 85 d8 fd ff ff 8b 85 d8 fd ff ff 89 85 d4 fd ff ff b8 00 00 50 00 50 b8 00 00 00 00 50 8b 85 d8 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c 8b 45 0c 8b 8d d8 fd ff ff 89 08 b8 3c 00 00 00 50 b8 00 00 00 00 50 8d 85 98 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c b8 3c 00 00 00 89 85 98 fd ff ff 8d 85 98 fd ff ff 83 c0 10 8d 8d dc fe ff ff 89 08 8d 85 98 fd ff ff 83 c0 14 b9 00 01 00 00 89 08 8d 85 98 fd ff ff 83 c0 2c 8d 8d dc fd ff ff 89 08 8d 85 98 fd ff ff 83 c0 30 b9 00 01 00 00 89 08 b8 0a 31 40 00 50 e8 ?? 0c 00 00 89 85 94 fd ff ff b8 16 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 fc b8 28 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 f8 b8 36 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f4 b8 47 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f0 b8 58 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 ec b8 69 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e8 b8 7a 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e4 b8 8e 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e0 8b 45 08 50 e8 ?? 0b 00 00 83 c4 04 8d 8d 98 fd ff ff 51 b9 00 00 00 00 51 50 8b 45 08 50 8b 45 fc ff d0 85 }
        $seq2 =  { b8 00 00 00 00 89 85 90 fd ff ff b8 00 00 00 00 89 85 8c fd ff ff b8 00 00 00 00 89 85 88 fd ff ff b8 00 00 00 00 89 85 84 fd ff ff b8 04 00 00 00 89 85 80 fd ff ff b8 00 00 00 00 88 85 7f f5 ff ff b8 00 08 00 00 50 b8 00 00 00 00 50 8d 85 80 f5 ff ff 50 e8 ?? 0b 00 00 83 c4 0c b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 9d 31 40 00 50 8b 45 f8 ff d0 89 85 90 fd ff ff 8b 85 }
        $s1 = "%s\\netfilter.sys" fullword ascii
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\netfilter" fullword ascii
        $s3 = "\\\\.\\netfilter" fullword ascii
   condition:
        uint16(0) == 0x5a4d 
        and filesize > 6KB and filesize < 1000KB
        and (all of ($seq*) or 2 of ($s*))
}

rule MAL_Netfilter_May_2021_1 {
   meta:
        description = "Detects Netfilter rootkit"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1405483373280235520"
        date = "2020-06-18"
        hash1 = "63d61549030fcf46ff1dc138122580b4364f0fe99e6b068bc6a3d6903656aff0"
        hash2 = "8249e9c0ac0840a36d9a5b9ff3e217198a2f533159acd4bf3d9b0132cc079870"
        hash3 = "d64f906376f21677d0585e93dae8b36248f94be7091b01fd1d4381916a326afe"
        tlp = "White"
        adversary = "Chinese APT Group"
        id = "0ac01eb3-435b-52b0-b8e8-ace2ebb34f60"
   strings:
        $seq1 = { 48 8b 05 a9 57 ff ff 45 33 c9 49 b8 32 a2 df 2d 99 2b 00 00 48 85 c0 74 05 49 3b c0 75 38 0f 31 48 c1 e2 20 48 8d 0d 85 57 ff ff 48 0b c2 48 33 c1 48 89 05 78 57 ff ff 66 44 89 0d 76 57 ff ff 48 8b 05 69 57 ff ff 48 85 c0 75 0a 49 8b c0 48 89 05 5a 57 ff ff 48 f7 d0 48 89 05 58 57 }
        $seq2 = { 48 83 ec 38 48 83 64 24 20 00 48 8d 05 83 4c 00 00 48 8d 15 24 d1 00 00 48 89 44 24 28 48 8d 4c 24 20 e8 4d 05 00 00 85 c0 78 16 4c 8d 05 22 d1 00 00 83 ca ff 48 8d 0d 00 d1 00 00 e8 39 05 00 00 48 83 c4 }
        $seq3 = { 45 33 c0 48 8d 4c 24 40 41 8d 50 01 ff 15 5d 62 00 00 c6 84 24 88 00 00 00 01 48 8d 84 24 88 00 00 00 48 89 46 18 48 8d 0d e2 fe ff ff 48 89 9e c0 00 00 00 48 8d 44 24 40 48 89 46 50 48 8d 44 24 30 48 89 46 48 65 48 8b 04 25 88 01 00 00 48 89 86 98 00 00 00 48 8b 86 b8 00 00 00 40 88 7e 40 c6 40 b8 06 4c 89 78 e0 48 89 58 e8 c7 40 c0 01 00 00 00 c7 40 c8 0d 00 00 00 48 89 58 d0 48 8b 86 b8 00 00 00 48 89 48 f0 48 8d 4c 24 40 48 89 48 f8 c6 40 bb e0 48 8b 43 28 48 85 c0 74 2f 48 8b 48 10 48 85 c9 74 07 48 21 78 10 4c 8b f1 48 8b 08 48 85 c9 74 06 48 21 38 48 8b e9 48 8b 48 08 48 85 c9 74 08 48 83 60 08 00 48 8b f9 48 8b d6 49 8b cf ff 15 74 61 00 00 3d 03 01 00 00 75 19 48 83 64 24 20 00 48 8d 4c 24 40 41 b1 01 45 33 c0 33 d2 ff 15 64 61 00 00 48 8b 43 28 48 85 c0 74 1a 4d }
        $seq4 = { 8b 84 24 80 00 00 00 48 8d 54 24 38 48 8b 4c 24 30 44 8b ce 89 44 24 28 45 33 c0 48 89 7c 24 20 ff 15 66 2e 00 00 48 8b 4c 24 30 8b d8 ff 15 49 2e 00 00 48 8b 4c 24 30 ff 15 26 2d 00 00 8b }
        $s1 = "%sc=%s" fullword ascii
        $s2 = { 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 }
        $s3 = "NETIO.SYS" fullword ascii
   condition:
        uint16(0) == 0x5a4d 
        and filesize > 20KB and filesize < 1000KB
        and (3 of ($seq*) or 2 of ($s*))
}