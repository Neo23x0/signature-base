import "pe"

rule APT_RU_APT27_HyperBro_Vftrace_Loader_Jan22_1 {
    meta:
        description = "Yara rule to detect first Hyperbro Loader Stage, often called vftrace.dll. Detects decoding function."
        author = "Bundesamt fuer Verfassungsschutz (modified by Florian Roth)"
        date = "2022-01-14"
        sharing = "TLP:WHITE"
        reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
        hash1 = "333B52C2CFAC56B86EE9D54AEF4F0FF4144528917BC1AA1FE1613EFC2318339A"
        id = "b049e163-2694-5fb9-a3a3-98cc77bcd0ca"
    strings:
        $decoder_routine = { 8A ?? 41 10 00 00 8B ?? 28 ?? ?? 4? 3B ?? 72 ?? }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        $decoder_routine and 
        pe.exports("D_C_Support_SetD_File")
}

rule APT_CN_APT27_Compromised_Certficate_Jan22_1 {
   meta:
      description = "Detects compromised certifcates used by APT27 malware"
      author = "Florian Roth (Nextron Systems)"
      date = "2022-01-29"
      score = 80
      reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
      id = "f2f015af-219d-51ab-9529-01687a879ebb"
   condition:
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         pe.signatures[i].serial == "08:68:70:51:50:f1:cf:c1:fc:c3:fc:91:a4:49:49:a6"
   )
}
rule HvS_APT27_HyperBro_Decrypted_Stage2 {
   meta:
      description = "HyperBro Stage 2 and compressed Stage 3 detection"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
      date = "2022-02-07"
      hash1 = "fc5a58bf0fce9cb96f35ee76842ff17816fe302e3164bc7c6a5ef46f6eff67ed"
      id = "039e5d41-eadb-5c53-82cd-20ffd4105326"
   strings:
      $lznt1_compressed_pe_header_small = { FC B9 00 4D 5A 90 } // This is the lznt1 compressed PE header

      $lznt1_compressed_pe_header_large_1 = { FC B9 00 4D 5A 90 00 03 00 00 00 82 04 00 30 FF FF 00 } 
      $lznt1_compressed_pe_header_large_2 = { 00 b8 00 38 0d 01 00 40 04 38 19 00 10 01 00 00 }
      $lznt1_compressed_pe_header_large_3 = { 00 0e 1f ba 0e 00 b4 09 cd 00 21 b8 01 4c cd 21 }
      $lznt1_compressed_pe_header_large_4 = { 54 68 00 69 73 20 70 72 6f 67 72 00 61 6d 20 63 }
      $lznt1_compressed_pe_header_large_5 = { 61 6e 6e 6f 00 74 20 62 65 20 72 75 6e 00 20 69 }
      $lznt1_compressed_pe_header_large_6 = { 6e 20 44 4f 53 20 00 6d 6f 64 65 2e 0d 0d 0a 02 }

   condition:
      filesize < 200KB and
      ($lznt1_compressed_pe_header_small at 0x9ce) or (all of ($lznt1_compressed_pe_header_large_*))
}

rule HvS_APT27_HyperBro_Stage3 {
   meta:
      description = "HyperBro Stage 3 detection - also tested in memory"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Markus Poelloth"
      reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
      date = "2022-02-07"
      modified = "2023-01-07"
      hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
      id = "b4002777-f129-5177-a8f1-690012a207fa"
   strings:
      $s1 = "\\cmd.exe /A" wide
      $s2 = "vftrace.dll" fullword wide
      $s3 = "msmpeng.exe" fullword wide
      $s4 = "\\\\.\\pipe\\testpipe" fullword wide
      $s5 = "thumb.dat" fullword wide

      $g1 = "%s\\%d.exe" fullword wide
      $g2 = "https://%s:%d/api/v2/ajax" fullword wide
      $g3 = " -k networkservice" fullword wide
      $g4 = " -k localservice" fullword wide
      
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      (( 4 of ($s*) ) or (4 of ($g*)))
}

rule HvS_APT27_HyperBro_Stage3_C2 {
   meta:
      description = "HyperBro Stage 3 C2 path and user agent detection - also tested in memory"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
      date = "2022-02-07"
      hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
      id = "d1fe03b9-440c-5127-9572-dddcd5c9966b"
   strings:
      $s1 = "api/v2/ajax" ascii wide nocase
      $s2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" ascii wide nocase
   condition:
      all of them
}


rule HvS_APT27_HyperBro_Stage3_Persistence {
   meta:
      description = "HyperBro Stage 3 registry keys for persistence"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marko Dorfhuber"
      reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
      date = "2022-02-07"
      hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
      id = "2bb1d28b-5fc4-5f0b-b546-c8b8192b0d48"
   strings:
      $ = "SOFTWARE\\WOW6432Node\\Microsoft\\config_" ascii
      $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\windefenders" ascii
   condition:
      1 of them
}


rule HvS_APT27_HyperBro_Encrypted_Stage2 {
   meta:
      description = "HyperBro Encrypted Stage 2 detection. Looks for all possible one byte shifts of the lznt1 compressed PE header"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
      date = "2022-02-07"
      hash1 = "fc5a58bf0fce9cb96f35ee76842ff17816fe302e3164bc7c6a5ef46f6eff67ed"
      id = "fa4fe057-4c3f-5785-a8d3-588398360996"
   strings:
      $encrypted_pe_header_shift_0 = { fc b9 00 4d 5a 90 00 03 00 00 00 82 04 00 30 ff ff 00 }
      $encrypted_pe_header_shift_1 = { fd ba 01 4e 5b 91 01 04 01 01 01 83 05 01 31 00 00 01 }
      $encrypted_pe_header_shift_2 = { fe bb 02 4f 5c 92 02 05 02 02 02 84 06 02 32 01 01 02 }
      $encrypted_pe_header_shift_3 = { ff bc 03 50 5d 93 03 06 03 03 03 85 07 03 33 02 02 03 }
      $encrypted_pe_header_shift_4 = { 00 bd 04 51 5e 94 04 07 04 04 04 86 08 04 34 03 03 04 }
      $encrypted_pe_header_shift_5 = { 01 be 05 52 5f 95 05 08 05 05 05 87 09 05 35 04 04 05 }
      $encrypted_pe_header_shift_6 = { 02 bf 06 53 60 96 06 09 06 06 06 88 0a 06 36 05 05 06 }
      $encrypted_pe_header_shift_7 = { 03 c0 07 54 61 97 07 0a 07 07 07 89 0b 07 37 06 06 07 }
      $encrypted_pe_header_shift_8 = { 04 c1 08 55 62 98 08 0b 08 08 08 8a 0c 08 38 07 07 08 }
      $encrypted_pe_header_shift_9 = { 05 c2 09 56 63 99 09 0c 09 09 09 8b 0d 09 39 08 08 09 }
      $encrypted_pe_header_shift_10 = { 06 c3 0a 57 64 9a 0a 0d 0a 0a 0a 8c 0e 0a 3a 09 09 0a }
      $encrypted_pe_header_shift_11 = { 07 c4 0b 58 65 9b 0b 0e 0b 0b 0b 8d 0f 0b 3b 0a 0a 0b }
      $encrypted_pe_header_shift_12 = { 08 c5 0c 59 66 9c 0c 0f 0c 0c 0c 8e 10 0c 3c 0b 0b 0c }
      $encrypted_pe_header_shift_13 = { 09 c6 0d 5a 67 9d 0d 10 0d 0d 0d 8f 11 0d 3d 0c 0c 0d }
      $encrypted_pe_header_shift_14 = { 0a c7 0e 5b 68 9e 0e 11 0e 0e 0e 90 12 0e 3e 0d 0d 0e }
      $encrypted_pe_header_shift_15 = { 0b c8 0f 5c 69 9f 0f 12 0f 0f 0f 91 13 0f 3f 0e 0e 0f }
      $encrypted_pe_header_shift_16 = { 0c c9 10 5d 6a a0 10 13 10 10 10 92 14 10 40 0f 0f 10 }
      $encrypted_pe_header_shift_17 = { 0d ca 11 5e 6b a1 11 14 11 11 11 93 15 11 41 10 10 11 }
      $encrypted_pe_header_shift_18 = { 0e cb 12 5f 6c a2 12 15 12 12 12 94 16 12 42 11 11 12 }
      $encrypted_pe_header_shift_19 = { 0f cc 13 60 6d a3 13 16 13 13 13 95 17 13 43 12 12 13 }
      $encrypted_pe_header_shift_20 = { 10 cd 14 61 6e a4 14 17 14 14 14 96 18 14 44 13 13 14 }
      $encrypted_pe_header_shift_21 = { 11 ce 15 62 6f a5 15 18 15 15 15 97 19 15 45 14 14 15 }
      $encrypted_pe_header_shift_22 = { 12 cf 16 63 70 a6 16 19 16 16 16 98 1a 16 46 15 15 16 }
      $encrypted_pe_header_shift_23 = { 13 d0 17 64 71 a7 17 1a 17 17 17 99 1b 17 47 16 16 17 }
      $encrypted_pe_header_shift_24 = { 14 d1 18 65 72 a8 18 1b 18 18 18 9a 1c 18 48 17 17 18 }
      $encrypted_pe_header_shift_25 = { 15 d2 19 66 73 a9 19 1c 19 19 19 9b 1d 19 49 18 18 19 }
      $encrypted_pe_header_shift_26 = { 16 d3 1a 67 74 aa 1a 1d 1a 1a 1a 9c 1e 1a 4a 19 19 1a }
      $encrypted_pe_header_shift_27 = { 17 d4 1b 68 75 ab 1b 1e 1b 1b 1b 9d 1f 1b 4b 1a 1a 1b }
      $encrypted_pe_header_shift_28 = { 18 d5 1c 69 76 ac 1c 1f 1c 1c 1c 9e 20 1c 4c 1b 1b 1c }
      $encrypted_pe_header_shift_29 = { 19 d6 1d 6a 77 ad 1d 20 1d 1d 1d 9f 21 1d 4d 1c 1c 1d }
      $encrypted_pe_header_shift_30 = { 1a d7 1e 6b 78 ae 1e 21 1e 1e 1e a0 22 1e 4e 1d 1d 1e }
      $encrypted_pe_header_shift_31 = { 1b d8 1f 6c 79 af 1f 22 1f 1f 1f a1 23 1f 4f 1e 1e 1f }
      $encrypted_pe_header_shift_32 = { 1c d9 20 6d 7a b0 20 23 20 20 20 a2 24 20 50 1f 1f 20 }
      $encrypted_pe_header_shift_33 = { 1d da 21 6e 7b b1 21 24 21 21 21 a3 25 21 51 20 20 21 }
      $encrypted_pe_header_shift_34 = { 1e db 22 6f 7c b2 22 25 22 22 22 a4 26 22 52 21 21 22 }
      $encrypted_pe_header_shift_35 = { 1f dc 23 70 7d b3 23 26 23 23 23 a5 27 23 53 22 22 23 }
      $encrypted_pe_header_shift_36 = { 20 dd 24 71 7e b4 24 27 24 24 24 a6 28 24 54 23 23 24 }
      $encrypted_pe_header_shift_37 = { 21 de 25 72 7f b5 25 28 25 25 25 a7 29 25 55 24 24 25 }
      $encrypted_pe_header_shift_38 = { 22 df 26 73 80 b6 26 29 26 26 26 a8 2a 26 56 25 25 26 }
      $encrypted_pe_header_shift_39 = { 23 e0 27 74 81 b7 27 2a 27 27 27 a9 2b 27 57 26 26 27 }
      $encrypted_pe_header_shift_40 = { 24 e1 28 75 82 b8 28 2b 28 28 28 aa 2c 28 58 27 27 28 }
      $encrypted_pe_header_shift_41 = { 25 e2 29 76 83 b9 29 2c 29 29 29 ab 2d 29 59 28 28 29 }
      $encrypted_pe_header_shift_42 = { 26 e3 2a 77 84 ba 2a 2d 2a 2a 2a ac 2e 2a 5a 29 29 2a }
      $encrypted_pe_header_shift_43 = { 27 e4 2b 78 85 bb 2b 2e 2b 2b 2b ad 2f 2b 5b 2a 2a 2b }
      $encrypted_pe_header_shift_44 = { 28 e5 2c 79 86 bc 2c 2f 2c 2c 2c ae 30 2c 5c 2b 2b 2c }
      $encrypted_pe_header_shift_45 = { 29 e6 2d 7a 87 bd 2d 30 2d 2d 2d af 31 2d 5d 2c 2c 2d }
      $encrypted_pe_header_shift_46 = { 2a e7 2e 7b 88 be 2e 31 2e 2e 2e b0 32 2e 5e 2d 2d 2e }
      $encrypted_pe_header_shift_47 = { 2b e8 2f 7c 89 bf 2f 32 2f 2f 2f b1 33 2f 5f 2e 2e 2f }
      $encrypted_pe_header_shift_48 = { 2c e9 30 7d 8a c0 30 33 30 30 30 b2 34 30 60 2f 2f 30 }
      $encrypted_pe_header_shift_49 = { 2d ea 31 7e 8b c1 31 34 31 31 31 b3 35 31 61 30 30 31 }
      $encrypted_pe_header_shift_50 = { 2e eb 32 7f 8c c2 32 35 32 32 32 b4 36 32 62 31 31 32 }
      $encrypted_pe_header_shift_51 = { 2f ec 33 80 8d c3 33 36 33 33 33 b5 37 33 63 32 32 33 }
      $encrypted_pe_header_shift_52 = { 30 ed 34 81 8e c4 34 37 34 34 34 b6 38 34 64 33 33 34 }
      $encrypted_pe_header_shift_53 = { 31 ee 35 82 8f c5 35 38 35 35 35 b7 39 35 65 34 34 35 }
      $encrypted_pe_header_shift_54 = { 32 ef 36 83 90 c6 36 39 36 36 36 b8 3a 36 66 35 35 36 }
      $encrypted_pe_header_shift_55 = { 33 f0 37 84 91 c7 37 3a 37 37 37 b9 3b 37 67 36 36 37 }
      $encrypted_pe_header_shift_56 = { 34 f1 38 85 92 c8 38 3b 38 38 38 ba 3c 38 68 37 37 38 }
      $encrypted_pe_header_shift_57 = { 35 f2 39 86 93 c9 39 3c 39 39 39 bb 3d 39 69 38 38 39 }
      $encrypted_pe_header_shift_58 = { 36 f3 3a 87 94 ca 3a 3d 3a 3a 3a bc 3e 3a 6a 39 39 3a }
      $encrypted_pe_header_shift_59 = { 37 f4 3b 88 95 cb 3b 3e 3b 3b 3b bd 3f 3b 6b 3a 3a 3b }
      $encrypted_pe_header_shift_60 = { 38 f5 3c 89 96 cc 3c 3f 3c 3c 3c be 40 3c 6c 3b 3b 3c }
      $encrypted_pe_header_shift_61 = { 39 f6 3d 8a 97 cd 3d 40 3d 3d 3d bf 41 3d 6d 3c 3c 3d }
      $encrypted_pe_header_shift_62 = { 3a f7 3e 8b 98 ce 3e 41 3e 3e 3e c0 42 3e 6e 3d 3d 3e }
      $encrypted_pe_header_shift_63 = { 3b f8 3f 8c 99 cf 3f 42 3f 3f 3f c1 43 3f 6f 3e 3e 3f }
      $encrypted_pe_header_shift_64 = { 3c f9 40 8d 9a d0 40 43 40 40 40 c2 44 40 70 3f 3f 40 }
      $encrypted_pe_header_shift_65 = { 3d fa 41 8e 9b d1 41 44 41 41 41 c3 45 41 71 40 40 41 }
      $encrypted_pe_header_shift_66 = { 3e fb 42 8f 9c d2 42 45 42 42 42 c4 46 42 72 41 41 42 }
      $encrypted_pe_header_shift_67 = { 3f fc 43 90 9d d3 43 46 43 43 43 c5 47 43 73 42 42 43 }
      $encrypted_pe_header_shift_68 = { 40 fd 44 91 9e d4 44 47 44 44 44 c6 48 44 74 43 43 44 }
      $encrypted_pe_header_shift_69 = { 41 fe 45 92 9f d5 45 48 45 45 45 c7 49 45 75 44 44 45 }
      $encrypted_pe_header_shift_70 = { 42 ff 46 93 a0 d6 46 49 46 46 46 c8 4a 46 76 45 45 46 }
      $encrypted_pe_header_shift_71 = { 43 00 47 94 a1 d7 47 4a 47 47 47 c9 4b 47 77 46 46 47 }
      $encrypted_pe_header_shift_72 = { 44 01 48 95 a2 d8 48 4b 48 48 48 ca 4c 48 78 47 47 48 }
      $encrypted_pe_header_shift_73 = { 45 02 49 96 a3 d9 49 4c 49 49 49 cb 4d 49 79 48 48 49 }
      $encrypted_pe_header_shift_74 = { 46 03 4a 97 a4 da 4a 4d 4a 4a 4a cc 4e 4a 7a 49 49 4a }
      $encrypted_pe_header_shift_75 = { 47 04 4b 98 a5 db 4b 4e 4b 4b 4b cd 4f 4b 7b 4a 4a 4b }
      $encrypted_pe_header_shift_76 = { 48 05 4c 99 a6 dc 4c 4f 4c 4c 4c ce 50 4c 7c 4b 4b 4c }
      $encrypted_pe_header_shift_77 = { 49 06 4d 9a a7 dd 4d 50 4d 4d 4d cf 51 4d 7d 4c 4c 4d }
      $encrypted_pe_header_shift_78 = { 4a 07 4e 9b a8 de 4e 51 4e 4e 4e d0 52 4e 7e 4d 4d 4e }
      $encrypted_pe_header_shift_79 = { 4b 08 4f 9c a9 df 4f 52 4f 4f 4f d1 53 4f 7f 4e 4e 4f }
      $encrypted_pe_header_shift_80 = { 4c 09 50 9d aa e0 50 53 50 50 50 d2 54 50 80 4f 4f 50 }
      $encrypted_pe_header_shift_81 = { 4d 0a 51 9e ab e1 51 54 51 51 51 d3 55 51 81 50 50 51 }
      $encrypted_pe_header_shift_82 = { 4e 0b 52 9f ac e2 52 55 52 52 52 d4 56 52 82 51 51 52 }
      $encrypted_pe_header_shift_83 = { 4f 0c 53 a0 ad e3 53 56 53 53 53 d5 57 53 83 52 52 53 }
      $encrypted_pe_header_shift_84 = { 50 0d 54 a1 ae e4 54 57 54 54 54 d6 58 54 84 53 53 54 }
      $encrypted_pe_header_shift_85 = { 51 0e 55 a2 af e5 55 58 55 55 55 d7 59 55 85 54 54 55 }
      $encrypted_pe_header_shift_86 = { 52 0f 56 a3 b0 e6 56 59 56 56 56 d8 5a 56 86 55 55 56 }
      $encrypted_pe_header_shift_87 = { 53 10 57 a4 b1 e7 57 5a 57 57 57 d9 5b 57 87 56 56 57 }
      $encrypted_pe_header_shift_88 = { 54 11 58 a5 b2 e8 58 5b 58 58 58 da 5c 58 88 57 57 58 }
      $encrypted_pe_header_shift_89 = { 55 12 59 a6 b3 e9 59 5c 59 59 59 db 5d 59 89 58 58 59 }
      $encrypted_pe_header_shift_90 = { 56 13 5a a7 b4 ea 5a 5d 5a 5a 5a dc 5e 5a 8a 59 59 5a }
      $encrypted_pe_header_shift_91 = { 57 14 5b a8 b5 eb 5b 5e 5b 5b 5b dd 5f 5b 8b 5a 5a 5b }
      $encrypted_pe_header_shift_92 = { 58 15 5c a9 b6 ec 5c 5f 5c 5c 5c de 60 5c 8c 5b 5b 5c }
      $encrypted_pe_header_shift_93 = { 59 16 5d aa b7 ed 5d 60 5d 5d 5d df 61 5d 8d 5c 5c 5d }
      $encrypted_pe_header_shift_94 = { 5a 17 5e ab b8 ee 5e 61 5e 5e 5e e0 62 5e 8e 5d 5d 5e }
      $encrypted_pe_header_shift_95 = { 5b 18 5f ac b9 ef 5f 62 5f 5f 5f e1 63 5f 8f 5e 5e 5f }
      $encrypted_pe_header_shift_96 = { 5c 19 60 ad ba f0 60 63 60 60 60 e2 64 60 90 5f 5f 60 }
      $encrypted_pe_header_shift_97 = { 5d 1a 61 ae bb f1 61 64 61 61 61 e3 65 61 91 60 60 61 }
      $encrypted_pe_header_shift_98 = { 5e 1b 62 af bc f2 62 65 62 62 62 e4 66 62 92 61 61 62 }
      $encrypted_pe_header_shift_99 = { 5f 1c 63 b0 bd f3 63 66 63 63 63 e5 67 63 93 62 62 63 }
      $encrypted_pe_header_shift_100 = { 60 1d 64 b1 be f4 64 67 64 64 64 e6 68 64 94 63 63 64 }
      $encrypted_pe_header_shift_101 = { 61 1e 65 b2 bf f5 65 68 65 65 65 e7 69 65 95 64 64 65 }
      $encrypted_pe_header_shift_102 = { 62 1f 66 b3 c0 f6 66 69 66 66 66 e8 6a 66 96 65 65 66 }
      $encrypted_pe_header_shift_103 = { 63 20 67 b4 c1 f7 67 6a 67 67 67 e9 6b 67 97 66 66 67 }
      $encrypted_pe_header_shift_104 = { 64 21 68 b5 c2 f8 68 6b 68 68 68 ea 6c 68 98 67 67 68 }
      $encrypted_pe_header_shift_105 = { 65 22 69 b6 c3 f9 69 6c 69 69 69 eb 6d 69 99 68 68 69 }
      $encrypted_pe_header_shift_106 = { 66 23 6a b7 c4 fa 6a 6d 6a 6a 6a ec 6e 6a 9a 69 69 6a }
      $encrypted_pe_header_shift_107 = { 67 24 6b b8 c5 fb 6b 6e 6b 6b 6b ed 6f 6b 9b 6a 6a 6b }
      $encrypted_pe_header_shift_108 = { 68 25 6c b9 c6 fc 6c 6f 6c 6c 6c ee 70 6c 9c 6b 6b 6c }
      $encrypted_pe_header_shift_109 = { 69 26 6d ba c7 fd 6d 70 6d 6d 6d ef 71 6d 9d 6c 6c 6d }
      $encrypted_pe_header_shift_110 = { 6a 27 6e bb c8 fe 6e 71 6e 6e 6e f0 72 6e 9e 6d 6d 6e }
      $encrypted_pe_header_shift_111 = { 6b 28 6f bc c9 ff 6f 72 6f 6f 6f f1 73 6f 9f 6e 6e 6f }
      $encrypted_pe_header_shift_112 = { 6c 29 70 bd ca 00 70 73 70 70 70 f2 74 70 a0 6f 6f 70 }
      $encrypted_pe_header_shift_113 = { 6d 2a 71 be cb 01 71 74 71 71 71 f3 75 71 a1 70 70 71 }
      $encrypted_pe_header_shift_114 = { 6e 2b 72 bf cc 02 72 75 72 72 72 f4 76 72 a2 71 71 72 }
      $encrypted_pe_header_shift_115 = { 6f 2c 73 c0 cd 03 73 76 73 73 73 f5 77 73 a3 72 72 73 }
      $encrypted_pe_header_shift_116 = { 70 2d 74 c1 ce 04 74 77 74 74 74 f6 78 74 a4 73 73 74 }
      $encrypted_pe_header_shift_117 = { 71 2e 75 c2 cf 05 75 78 75 75 75 f7 79 75 a5 74 74 75 }
      $encrypted_pe_header_shift_118 = { 72 2f 76 c3 d0 06 76 79 76 76 76 f8 7a 76 a6 75 75 76 }
      $encrypted_pe_header_shift_119 = { 73 30 77 c4 d1 07 77 7a 77 77 77 f9 7b 77 a7 76 76 77 }
      $encrypted_pe_header_shift_120 = { 74 31 78 c5 d2 08 78 7b 78 78 78 fa 7c 78 a8 77 77 78 }
      $encrypted_pe_header_shift_121 = { 75 32 79 c6 d3 09 79 7c 79 79 79 fb 7d 79 a9 78 78 79 }
      $encrypted_pe_header_shift_122 = { 76 33 7a c7 d4 0a 7a 7d 7a 7a 7a fc 7e 7a aa 79 79 7a }
      $encrypted_pe_header_shift_123 = { 77 34 7b c8 d5 0b 7b 7e 7b 7b 7b fd 7f 7b ab 7a 7a 7b }
      $encrypted_pe_header_shift_124 = { 78 35 7c c9 d6 0c 7c 7f 7c 7c 7c fe 80 7c ac 7b 7b 7c }
      $encrypted_pe_header_shift_125 = { 79 36 7d ca d7 0d 7d 80 7d 7d 7d ff 81 7d ad 7c 7c 7d }
      $encrypted_pe_header_shift_126 = { 7a 37 7e cb d8 0e 7e 81 7e 7e 7e 00 82 7e ae 7d 7d 7e }
      $encrypted_pe_header_shift_127 = { 7b 38 7f cc d9 0f 7f 82 7f 7f 7f 01 83 7f af 7e 7e 7f }
      $encrypted_pe_header_shift_128 = { 7c 39 80 cd da 10 80 83 80 80 80 02 84 80 b0 7f 7f 80 }
      $encrypted_pe_header_shift_129 = { 7d 3a 81 ce db 11 81 84 81 81 81 03 85 81 b1 80 80 81 }
      $encrypted_pe_header_shift_130 = { 7e 3b 82 cf dc 12 82 85 82 82 82 04 86 82 b2 81 81 82 }
      $encrypted_pe_header_shift_131 = { 7f 3c 83 d0 dd 13 83 86 83 83 83 05 87 83 b3 82 82 83 }
      $encrypted_pe_header_shift_132 = { 80 3d 84 d1 de 14 84 87 84 84 84 06 88 84 b4 83 83 84 }
      $encrypted_pe_header_shift_133 = { 81 3e 85 d2 df 15 85 88 85 85 85 07 89 85 b5 84 84 85 }
      $encrypted_pe_header_shift_134 = { 82 3f 86 d3 e0 16 86 89 86 86 86 08 8a 86 b6 85 85 86 }
      $encrypted_pe_header_shift_135 = { 83 40 87 d4 e1 17 87 8a 87 87 87 09 8b 87 b7 86 86 87 }
      $encrypted_pe_header_shift_136 = { 84 41 88 d5 e2 18 88 8b 88 88 88 0a 8c 88 b8 87 87 88 }
      $encrypted_pe_header_shift_137 = { 85 42 89 d6 e3 19 89 8c 89 89 89 0b 8d 89 b9 88 88 89 }
      $encrypted_pe_header_shift_138 = { 86 43 8a d7 e4 1a 8a 8d 8a 8a 8a 0c 8e 8a ba 89 89 8a }
      $encrypted_pe_header_shift_139 = { 87 44 8b d8 e5 1b 8b 8e 8b 8b 8b 0d 8f 8b bb 8a 8a 8b }
      $encrypted_pe_header_shift_140 = { 88 45 8c d9 e6 1c 8c 8f 8c 8c 8c 0e 90 8c bc 8b 8b 8c }
      $encrypted_pe_header_shift_141 = { 89 46 8d da e7 1d 8d 90 8d 8d 8d 0f 91 8d bd 8c 8c 8d }
      $encrypted_pe_header_shift_142 = { 8a 47 8e db e8 1e 8e 91 8e 8e 8e 10 92 8e be 8d 8d 8e }
      $encrypted_pe_header_shift_143 = { 8b 48 8f dc e9 1f 8f 92 8f 8f 8f 11 93 8f bf 8e 8e 8f }
      $encrypted_pe_header_shift_144 = { 8c 49 90 dd ea 20 90 93 90 90 90 12 94 90 c0 8f 8f 90 }
      $encrypted_pe_header_shift_145 = { 8d 4a 91 de eb 21 91 94 91 91 91 13 95 91 c1 90 90 91 }
      $encrypted_pe_header_shift_146 = { 8e 4b 92 df ec 22 92 95 92 92 92 14 96 92 c2 91 91 92 }
      $encrypted_pe_header_shift_147 = { 8f 4c 93 e0 ed 23 93 96 93 93 93 15 97 93 c3 92 92 93 }
      $encrypted_pe_header_shift_148 = { 90 4d 94 e1 ee 24 94 97 94 94 94 16 98 94 c4 93 93 94 }
      $encrypted_pe_header_shift_149 = { 91 4e 95 e2 ef 25 95 98 95 95 95 17 99 95 c5 94 94 95 }
      $encrypted_pe_header_shift_150 = { 92 4f 96 e3 f0 26 96 99 96 96 96 18 9a 96 c6 95 95 96 }
      $encrypted_pe_header_shift_151 = { 93 50 97 e4 f1 27 97 9a 97 97 97 19 9b 97 c7 96 96 97 }
      $encrypted_pe_header_shift_152 = { 94 51 98 e5 f2 28 98 9b 98 98 98 1a 9c 98 c8 97 97 98 }
      $encrypted_pe_header_shift_153 = { 95 52 99 e6 f3 29 99 9c 99 99 99 1b 9d 99 c9 98 98 99 }
      $encrypted_pe_header_shift_154 = { 96 53 9a e7 f4 2a 9a 9d 9a 9a 9a 1c 9e 9a ca 99 99 9a }
      $encrypted_pe_header_shift_155 = { 97 54 9b e8 f5 2b 9b 9e 9b 9b 9b 1d 9f 9b cb 9a 9a 9b }
      $encrypted_pe_header_shift_156 = { 98 55 9c e9 f6 2c 9c 9f 9c 9c 9c 1e a0 9c cc 9b 9b 9c }
      $encrypted_pe_header_shift_157 = { 99 56 9d ea f7 2d 9d a0 9d 9d 9d 1f a1 9d cd 9c 9c 9d }
      $encrypted_pe_header_shift_158 = { 9a 57 9e eb f8 2e 9e a1 9e 9e 9e 20 a2 9e ce 9d 9d 9e }
      $encrypted_pe_header_shift_159 = { 9b 58 9f ec f9 2f 9f a2 9f 9f 9f 21 a3 9f cf 9e 9e 9f }
      $encrypted_pe_header_shift_160 = { 9c 59 a0 ed fa 30 a0 a3 a0 a0 a0 22 a4 a0 d0 9f 9f a0 }
      $encrypted_pe_header_shift_161 = { 9d 5a a1 ee fb 31 a1 a4 a1 a1 a1 23 a5 a1 d1 a0 a0 a1 }
      $encrypted_pe_header_shift_162 = { 9e 5b a2 ef fc 32 a2 a5 a2 a2 a2 24 a6 a2 d2 a1 a1 a2 }
      $encrypted_pe_header_shift_163 = { 9f 5c a3 f0 fd 33 a3 a6 a3 a3 a3 25 a7 a3 d3 a2 a2 a3 }
      $encrypted_pe_header_shift_164 = { a0 5d a4 f1 fe 34 a4 a7 a4 a4 a4 26 a8 a4 d4 a3 a3 a4 }
      $encrypted_pe_header_shift_165 = { a1 5e a5 f2 ff 35 a5 a8 a5 a5 a5 27 a9 a5 d5 a4 a4 a5 }
      $encrypted_pe_header_shift_166 = { a2 5f a6 f3 00 36 a6 a9 a6 a6 a6 28 aa a6 d6 a5 a5 a6 }
      $encrypted_pe_header_shift_167 = { a3 60 a7 f4 01 37 a7 aa a7 a7 a7 29 ab a7 d7 a6 a6 a7 }
      $encrypted_pe_header_shift_168 = { a4 61 a8 f5 02 38 a8 ab a8 a8 a8 2a ac a8 d8 a7 a7 a8 }
      $encrypted_pe_header_shift_169 = { a5 62 a9 f6 03 39 a9 ac a9 a9 a9 2b ad a9 d9 a8 a8 a9 }
      $encrypted_pe_header_shift_170 = { a6 63 aa f7 04 3a aa ad aa aa aa 2c ae aa da a9 a9 aa }
      $encrypted_pe_header_shift_171 = { a7 64 ab f8 05 3b ab ae ab ab ab 2d af ab db aa aa ab }
      $encrypted_pe_header_shift_172 = { a8 65 ac f9 06 3c ac af ac ac ac 2e b0 ac dc ab ab ac }
      $encrypted_pe_header_shift_173 = { a9 66 ad fa 07 3d ad b0 ad ad ad 2f b1 ad dd ac ac ad }
      $encrypted_pe_header_shift_174 = { aa 67 ae fb 08 3e ae b1 ae ae ae 30 b2 ae de ad ad ae }
      $encrypted_pe_header_shift_175 = { ab 68 af fc 09 3f af b2 af af af 31 b3 af df ae ae af }
      $encrypted_pe_header_shift_176 = { ac 69 b0 fd 0a 40 b0 b3 b0 b0 b0 32 b4 b0 e0 af af b0 }
      $encrypted_pe_header_shift_177 = { ad 6a b1 fe 0b 41 b1 b4 b1 b1 b1 33 b5 b1 e1 b0 b0 b1 }
      $encrypted_pe_header_shift_178 = { ae 6b b2 ff 0c 42 b2 b5 b2 b2 b2 34 b6 b2 e2 b1 b1 b2 }
      $encrypted_pe_header_shift_179 = { af 6c b3 00 0d 43 b3 b6 b3 b3 b3 35 b7 b3 e3 b2 b2 b3 }
      $encrypted_pe_header_shift_180 = { b0 6d b4 01 0e 44 b4 b7 b4 b4 b4 36 b8 b4 e4 b3 b3 b4 }
      $encrypted_pe_header_shift_181 = { b1 6e b5 02 0f 45 b5 b8 b5 b5 b5 37 b9 b5 e5 b4 b4 b5 }
      $encrypted_pe_header_shift_182 = { b2 6f b6 03 10 46 b6 b9 b6 b6 b6 38 ba b6 e6 b5 b5 b6 }
      $encrypted_pe_header_shift_183 = { b3 70 b7 04 11 47 b7 ba b7 b7 b7 39 bb b7 e7 b6 b6 b7 }
      $encrypted_pe_header_shift_184 = { b4 71 b8 05 12 48 b8 bb b8 b8 b8 3a bc b8 e8 b7 b7 b8 }
      $encrypted_pe_header_shift_185 = { b5 72 b9 06 13 49 b9 bc b9 b9 b9 3b bd b9 e9 b8 b8 b9 }
      $encrypted_pe_header_shift_186 = { b6 73 ba 07 14 4a ba bd ba ba ba 3c be ba ea b9 b9 ba }
      $encrypted_pe_header_shift_187 = { b7 74 bb 08 15 4b bb be bb bb bb 3d bf bb eb ba ba bb }
      $encrypted_pe_header_shift_188 = { b8 75 bc 09 16 4c bc bf bc bc bc 3e c0 bc ec bb bb bc }
      $encrypted_pe_header_shift_189 = { b9 76 bd 0a 17 4d bd c0 bd bd bd 3f c1 bd ed bc bc bd }
      $encrypted_pe_header_shift_190 = { ba 77 be 0b 18 4e be c1 be be be 40 c2 be ee bd bd be }
      $encrypted_pe_header_shift_191 = { bb 78 bf 0c 19 4f bf c2 bf bf bf 41 c3 bf ef be be bf }
      $encrypted_pe_header_shift_192 = { bc 79 c0 0d 1a 50 c0 c3 c0 c0 c0 42 c4 c0 f0 bf bf c0 }
      $encrypted_pe_header_shift_193 = { bd 7a c1 0e 1b 51 c1 c4 c1 c1 c1 43 c5 c1 f1 c0 c0 c1 }
      $encrypted_pe_header_shift_194 = { be 7b c2 0f 1c 52 c2 c5 c2 c2 c2 44 c6 c2 f2 c1 c1 c2 }
      $encrypted_pe_header_shift_195 = { bf 7c c3 10 1d 53 c3 c6 c3 c3 c3 45 c7 c3 f3 c2 c2 c3 }
      $encrypted_pe_header_shift_196 = { c0 7d c4 11 1e 54 c4 c7 c4 c4 c4 46 c8 c4 f4 c3 c3 c4 }
      $encrypted_pe_header_shift_197 = { c1 7e c5 12 1f 55 c5 c8 c5 c5 c5 47 c9 c5 f5 c4 c4 c5 }
      $encrypted_pe_header_shift_198 = { c2 7f c6 13 20 56 c6 c9 c6 c6 c6 48 ca c6 f6 c5 c5 c6 }
      $encrypted_pe_header_shift_199 = { c3 80 c7 14 21 57 c7 ca c7 c7 c7 49 cb c7 f7 c6 c6 c7 }
      $encrypted_pe_header_shift_200 = { c4 81 c8 15 22 58 c8 cb c8 c8 c8 4a cc c8 f8 c7 c7 c8 }
      $encrypted_pe_header_shift_201 = { c5 82 c9 16 23 59 c9 cc c9 c9 c9 4b cd c9 f9 c8 c8 c9 }
      $encrypted_pe_header_shift_202 = { c6 83 ca 17 24 5a ca cd ca ca ca 4c ce ca fa c9 c9 ca }
      $encrypted_pe_header_shift_203 = { c7 84 cb 18 25 5b cb ce cb cb cb 4d cf cb fb ca ca cb }
      $encrypted_pe_header_shift_204 = { c8 85 cc 19 26 5c cc cf cc cc cc 4e d0 cc fc cb cb cc }
      $encrypted_pe_header_shift_205 = { c9 86 cd 1a 27 5d cd d0 cd cd cd 4f d1 cd fd cc cc cd }
      $encrypted_pe_header_shift_206 = { ca 87 ce 1b 28 5e ce d1 ce ce ce 50 d2 ce fe cd cd ce }
      $encrypted_pe_header_shift_207 = { cb 88 cf 1c 29 5f cf d2 cf cf cf 51 d3 cf ff ce ce cf }
      $encrypted_pe_header_shift_208 = { cc 89 d0 1d 2a 60 d0 d3 d0 d0 d0 52 d4 d0 00 cf cf d0 }
      $encrypted_pe_header_shift_209 = { cd 8a d1 1e 2b 61 d1 d4 d1 d1 d1 53 d5 d1 01 d0 d0 d1 }
      $encrypted_pe_header_shift_210 = { ce 8b d2 1f 2c 62 d2 d5 d2 d2 d2 54 d6 d2 02 d1 d1 d2 }
      $encrypted_pe_header_shift_211 = { cf 8c d3 20 2d 63 d3 d6 d3 d3 d3 55 d7 d3 03 d2 d2 d3 }
      $encrypted_pe_header_shift_212 = { d0 8d d4 21 2e 64 d4 d7 d4 d4 d4 56 d8 d4 04 d3 d3 d4 }
      $encrypted_pe_header_shift_213 = { d1 8e d5 22 2f 65 d5 d8 d5 d5 d5 57 d9 d5 05 d4 d4 d5 }
      $encrypted_pe_header_shift_214 = { d2 8f d6 23 30 66 d6 d9 d6 d6 d6 58 da d6 06 d5 d5 d6 }
      $encrypted_pe_header_shift_215 = { d3 90 d7 24 31 67 d7 da d7 d7 d7 59 db d7 07 d6 d6 d7 }
      $encrypted_pe_header_shift_216 = { d4 91 d8 25 32 68 d8 db d8 d8 d8 5a dc d8 08 d7 d7 d8 }
      $encrypted_pe_header_shift_217 = { d5 92 d9 26 33 69 d9 dc d9 d9 d9 5b dd d9 09 d8 d8 d9 }
      $encrypted_pe_header_shift_218 = { d6 93 da 27 34 6a da dd da da da 5c de da 0a d9 d9 da }
      $encrypted_pe_header_shift_219 = { d7 94 db 28 35 6b db de db db db 5d df db 0b da da db }
      $encrypted_pe_header_shift_220 = { d8 95 dc 29 36 6c dc df dc dc dc 5e e0 dc 0c db db dc }
      $encrypted_pe_header_shift_221 = { d9 96 dd 2a 37 6d dd e0 dd dd dd 5f e1 dd 0d dc dc dd }
      $encrypted_pe_header_shift_222 = { da 97 de 2b 38 6e de e1 de de de 60 e2 de 0e dd dd de }
      $encrypted_pe_header_shift_223 = { db 98 df 2c 39 6f df e2 df df df 61 e3 df 0f de de df }
      $encrypted_pe_header_shift_224 = { dc 99 e0 2d 3a 70 e0 e3 e0 e0 e0 62 e4 e0 10 df df e0 }
      $encrypted_pe_header_shift_225 = { dd 9a e1 2e 3b 71 e1 e4 e1 e1 e1 63 e5 e1 11 e0 e0 e1 }
      $encrypted_pe_header_shift_226 = { de 9b e2 2f 3c 72 e2 e5 e2 e2 e2 64 e6 e2 12 e1 e1 e2 }
      $encrypted_pe_header_shift_227 = { df 9c e3 30 3d 73 e3 e6 e3 e3 e3 65 e7 e3 13 e2 e2 e3 }
      $encrypted_pe_header_shift_228 = { e0 9d e4 31 3e 74 e4 e7 e4 e4 e4 66 e8 e4 14 e3 e3 e4 }
      $encrypted_pe_header_shift_229 = { e1 9e e5 32 3f 75 e5 e8 e5 e5 e5 67 e9 e5 15 e4 e4 e5 }
      $encrypted_pe_header_shift_230 = { e2 9f e6 33 40 76 e6 e9 e6 e6 e6 68 ea e6 16 e5 e5 e6 }
      $encrypted_pe_header_shift_231 = { e3 a0 e7 34 41 77 e7 ea e7 e7 e7 69 eb e7 17 e6 e6 e7 }
      $encrypted_pe_header_shift_232 = { e4 a1 e8 35 42 78 e8 eb e8 e8 e8 6a ec e8 18 e7 e7 e8 }
      $encrypted_pe_header_shift_233 = { e5 a2 e9 36 43 79 e9 ec e9 e9 e9 6b ed e9 19 e8 e8 e9 }
      $encrypted_pe_header_shift_234 = { e6 a3 ea 37 44 7a ea ed ea ea ea 6c ee ea 1a e9 e9 ea }
      $encrypted_pe_header_shift_235 = { e7 a4 eb 38 45 7b eb ee eb eb eb 6d ef eb 1b ea ea eb }
      $encrypted_pe_header_shift_236 = { e8 a5 ec 39 46 7c ec ef ec ec ec 6e f0 ec 1c eb eb ec }
      $encrypted_pe_header_shift_237 = { e9 a6 ed 3a 47 7d ed f0 ed ed ed 6f f1 ed 1d ec ec ed }
      $encrypted_pe_header_shift_238 = { ea a7 ee 3b 48 7e ee f1 ee ee ee 70 f2 ee 1e ed ed ee }
      $encrypted_pe_header_shift_239 = { eb a8 ef 3c 49 7f ef f2 ef ef ef 71 f3 ef 1f ee ee ef }
      $encrypted_pe_header_shift_240 = { ec a9 f0 3d 4a 80 f0 f3 f0 f0 f0 72 f4 f0 20 ef ef f0 }
      $encrypted_pe_header_shift_241 = { ed aa f1 3e 4b 81 f1 f4 f1 f1 f1 73 f5 f1 21 f0 f0 f1 }
      $encrypted_pe_header_shift_242 = { ee ab f2 3f 4c 82 f2 f5 f2 f2 f2 74 f6 f2 22 f1 f1 f2 }
      $encrypted_pe_header_shift_243 = { ef ac f3 40 4d 83 f3 f6 f3 f3 f3 75 f7 f3 23 f2 f2 f3 }
      $encrypted_pe_header_shift_244 = { f0 ad f4 41 4e 84 f4 f7 f4 f4 f4 76 f8 f4 24 f3 f3 f4 }
      $encrypted_pe_header_shift_245 = { f1 ae f5 42 4f 85 f5 f8 f5 f5 f5 77 f9 f5 25 f4 f4 f5 }
      $encrypted_pe_header_shift_246 = { f2 af f6 43 50 86 f6 f9 f6 f6 f6 78 fa f6 26 f5 f5 f6 }
      $encrypted_pe_header_shift_247 = { f3 b0 f7 44 51 87 f7 fa f7 f7 f7 79 fb f7 27 f6 f6 f7 }
      $encrypted_pe_header_shift_248 = { f4 b1 f8 45 52 88 f8 fb f8 f8 f8 7a fc f8 28 f7 f7 f8 }
      $encrypted_pe_header_shift_249 = { f5 b2 f9 46 53 89 f9 fc f9 f9 f9 7b fd f9 29 f8 f8 f9 }
      $encrypted_pe_header_shift_250 = { f6 b3 fa 47 54 8a fa fd fa fa fa 7c fe fa 2a f9 f9 fa }
      $encrypted_pe_header_shift_251 = { f7 b4 fb 48 55 8b fb fe fb fb fb 7d ff fb 2b fa fa fb }
      $encrypted_pe_header_shift_252 = { f8 b5 fc 49 56 8c fc ff fc fc fc 7e 00 fc 2c fb fb fc }
      $encrypted_pe_header_shift_253 = { f9 b6 fd 4a 57 8d fd 00 fd fd fd 7f 01 fd 2d fc fc fd }
      $encrypted_pe_header_shift_254 = { fa b7 fe 4b 58 8e fe 01 fe fe fe 80 02 fe 2e fd fd fe }
      $encrypted_pe_header_shift_255 = { fb b8 ff 4c 59 8f ff 02 ff ff ff 81 03 ff 2f fe fe ff }

   condition:
      filesize < 200KB and (1 of ($encrypted_pe_header_shift_*))
}
