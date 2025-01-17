
rule APT_IN_TA397_wmRAT {
    meta:
        author = "Proofpoint"
        description = "track wmRAT based on socket usage, odd error handling, and reused strings"
        date = "2024-11-20"
        category = "hunting"
        malfamily = "wmRAT"
        version = "1.0"
        score = 75
        reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
        hash = "3bf4bbd5564f4381820fb8da5810bd4d9718b5c80a7e8f055961007c6f30da2b"
        hash = "3e9a08972b8ec9c2e64eeb46ce1db92ae3c40bc8de48d278ba4d436fc3c8b3a4"
        hash = "40ddb4463be9d8131f363fd78e21d9de5d838a3ec4044526aea45a473d6ddd61"
        hash = "4836cb7eed0b20da50acb26472f918b180917101c026ce36074e0e879b604308"
        hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
        hash = "5ab76cf85ade810b7ae449e3dff8a19a018174ced45d37062c86568d9b7633f9"
        hash = "811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a"
        hash = "b588a423b826b57dce72c9ab58f89be2ddc710a0367ed0eed001c047d8bef32a"
        hash = "caf871247b7256945598816e9c5461d64b6bdb68a15ff9f8742ca31dc00865f8"
        id = "c5855b30-3e75-570f-b327-498dfc382159"
    strings:
        $code_sleep_loop = {
            6a 64              // push    0x64
            ff d6              // call    esi
            6a 01              // push    0x1
            e8 ?? ?? ?? ??     // call    operator new
            83 c4 04           // add     esp, 0x4
            3b c7              // cmp     eax, edi

        }
        $code_error_handling = {
            88 19           // mov     byte [ecx], bl
            4a              // dec     edx
            41              // inc     ecx
            47              // inc     edi
            4e              // dec     esi
            85 d2           // test    edx, edx
            ?? ??           // jne     0x401070
            5f              // pop     edi {__saved_edi}
            49              // dec     ecx
            5e              // pop     esi {__saved_esi}
            b8 7a 00 07 80  // mov     eax, 0x8007007a

        }
        $code_socket_recv_parsing = {
            // 8b 15 20 55 41 00   mov     edx, dword [data_415520]
            6a 00              // push    0x0
            b8 04 00 00 00     // mov     eax, 0x4
            2b c6              // sub     eax, esi
            50                 // push    eax {var_10_1}
            8d 0c 3e           // lea     ecx, [esi+edi]
            51                 // push    ecx {var_14_1}
            52                 // push    edx {var_18_1}
            ff ??              // call    ebx
            83 f8 ff           // cmp     eax, 0xffffffff
            ?? ??              // je      0x4082e3
            03 f0              // add     esi, eax
            83 fe 04           // cmp     esi, 0x4
          }

          $str1 = "-.-.-." ascii
          $str2 = "PATH" ascii
          $str3 = "Path=" ascii
          $str4 = "https://microsoft.com" ascii
          $str5 = "%s%ld M" ascii
          $str6 = "%s%ld K" ascii
          $str7 = "%s(%ld)" ascii
          $str8 = "RFOX" ascii
          $str9 = "1llll" ascii
          $str10 = "%d result(s)" ascii
          $str11 = "%s%ld MB" ascii
          $str12 = "%s%ld KB" ascii
          $str13 = "%.1f" ascii
          $str14 = "%02d-%02d-%d %02d:%02d" ascii
    condition:
          uint16be(0x0) == 0x4d5a and
          (2 of ($code*) or 10 of ($str*))

}

rule SUSP_RAR_NTFS_ADS {
    meta:
        description = "Detects RAR archive with NTFS alternate data stream"
        author = "Proofpoint"
        category = "hunting"
        score = 70
        date = "2024-12-17"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
        hash1 = "feec47858379c29300d249d1693f68dc085300f493891d1a9d4ea83b8db6e3c3"
        hash2 = "53a653aae9678075276bdb8ccf5eaff947f9121f73b8dcf24858c0447922d0b1"
        id = "ca2b5904-b3d3-53cd-a973-6f30f0831a94"
    strings:
        // RAR file format documentation: https://www.rarlab.com/technote.htm
        $rar_magic = {52 61 72 21} // RAR magic bytes (will match on any RAR version, we don't restrict on v5 for now, but on offset 0 which does not have to be the case according to the documentation)
        $ads = {
                 03         // Header Type -> Service Header
                 23         // Header flags
                 [17-20]    // Flags and extra data area
                 00         // Windows
                 03         // Length of name = STM = 3
                 53 54 4d   // STM NTFS alternate data stream
                 [1-2]      // variable int (vint) for size of the stream name -> 1-2 bytes should be enough to take into account
                 07         // Data type = Service data = Service header data array
                 3a         // Start of the ADS name -> start with colon ":"
               }
        $neg = "Zone.Identifier"  // This is the default Windows ADS name, we will get FPs on that, so we don't want that to be the first ADS name we find
    condition:
        $rar_magic at 0 and $ads and not $neg in (@ads[1]..@ads[1]+15)
}
