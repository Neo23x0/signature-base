import "pe"

rule MAL_APT_NK_Andariel_ScheduledTask_Loader {
   meta:
      author = "CISA.gov"
      description = "Detects a scheduled task loader used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "0c32758b-480c-5784-b28f-cee85d038850"
   strings:
      $obfuscation1 = { B8 02 00 00 00 48 6B C0 00 B9 CD FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 01 B9 CC FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 02 B9 8D FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 03 B9 9A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 04 B9 8C FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 05 B9 8A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 06 33 C9 66 89 8C 04 60 01 00 00 }
      $obfuscation2 = { 48 6B C0 02 C6 44 04 20 BA B8 01 00 00 00 48 6B C0 03 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 04 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 05 C6 44 04 20 8A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 9C B8 01 00 00 00 }
      $obfuscation3 = { 48 6B C0 00 C6 44 04 20 A8 B8 01 00 00 00 48 6B C0 01 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 02 C6 44 04 20 93 B8 01 00 00 00 48 6B C0 03 C6 44 04 20 96 B8 01 00 00 00 48 6B C0 04 C6 44 04 20 B9 B8 01 00 00 00 48 6B C0 05 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 07 C6 44 04 20 9E B8 01 00 00 00 48 6B C0 08 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 09 C6 44 04 20 8D B8 01 00 00 00 48 6B C0 0A C6 44 04 20 BC B8 01 00 00 00 }
   condition:
      uint16(0) == 0x5A4D 
      and $obfuscation1 and $obfuscation2 and $obfuscation3
}

rule MAL_APT_NK_Andariel_KaosRAT_Yamabot {
   meta:
      author = "CISA.gov"
      description = "Detects the KaosRAT variant"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 70
      id = "cdde69cd-1b38-52f5-8552-cef2cf4ad69c"
   strings:
      $str1 = "/kaos/"
      $str2 = "Abstand ["
      $str3 = "] anwenden"
      $str4 = "cmVjYXB0Y2hh"
      $str5 = "/bin/sh"
      $str6 = "utilities.CIpaddress"
      $str7 = "engine.NewEgg"
      $str8 = "%s%04x%s%s%s"
      $str9 = "Y2FwdGNoYV9zZXNzaW9u"
      $str10 = "utilities.EierKochen"
      $str11 = "kandidatKaufhaus"
   condition:
      3 of them
}

rule MAL_APT_NK_TriFaux_EasyRAT_JUPITER {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the EasyRAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "8bd72287-59da-53cf-9015-66149303e59f"
   strings:
      $InitOnce = "InitOnceExecuteOnce"
      $BREAK = { 0D 00 0A 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 0D 00 0A }
      $Bytes = "4C,$00,$00,$00,$01,$14,$02,$00,$00,$00,$00,$00,$C0,$00,$00,$00,$00,$00,$00," wide
   condition:
      uint16(0) == 0x5a4d 
      and all of them
}

rule MAL_APT_NK_Andariel_CutieDrop_MagicRAT {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the MagicRAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "104244de-83fb-5112-a2b6-e20d38a6ced6"
   strings:
      // I removed the 'wide' from the strings because the samples don't contain the strings
      // UTF-16 formatted and there's no indication that they ever will be, F.R.

      $config_os_w = "os/windows" ascii
      $config_os_l = "os/linux" ascii
      $config_os_m = "os/mac" ascii
      $config_comp_msft = "company/microsoft" ascii
      $config_comp_orcl = "company/oracle" ascii
      $POST_field_1 = "session=" ascii
      $POST_field_2 = "type=" ascii
      // $POST_field_3 = "id=" ascii wide  // disabled this string because it's too short
      $command_misspelled = "renmae" ascii
   condition:
      uint16(0) == 0x5a4d 
      and 7 of them
}

rule MAL_APT_NK_Andariel_HHSD_FileTransferTool {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the HHSD File Transfer Tool"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2025-07-09"
      score = 70
      id = "46b6dbaf-1272-5bbd-a586-5e48ba6c5022"
   strings:
      // 30 4D C7                xor     [rbp+buffer_v41+3], cl
      // 81 7D C4 22 C0 78 00    cmp      dword ptr [rbp+buffer_v41], 78C022h
      // 44 88 83 00 01 00 00    mov      [rbx+100h], r8b
      $handshake = { 30 ?? ?? 81 7? ?? 22 C0 78 00 4? 88 }
      
      // B1 14                   mov     cl, 14h
      // C7 45 F7 14 00 41 00    mov      [rbp+57h+Src], 410014h
      // C7 45 FB 7A 00 7F 00    mov      [rbp+57h+var_5C], 7F007Ah
      // C7 45 FF 7B 00 63 00    mov     [rbp+57h+var_58], 63007Bh
      // C7 45 03 7A 00 34 00    mov      [rbp+57h+var_54], 34007Ah
      // C7 45 07 51 00 66 00    mov      [rbp+57h+var_50], 660051h
      // C7 45 0B 66 00 7B 00    mov      [rbp+57h+var_4C], 7B0066h
      // C7 45 0F 66 00 00 00    mov      [rbp+57h+var_48], 66h ; 'f'
      $err_xor_str = { 14 C7 [2] 14 00 41 00 C7 [2] 7A 00 7F 00 C7 [2] 7B 00 63 00 C7 [2] 7A 00 34 00 }
      
      // 41 02 D0                add     dl, r8b
      // 44 02 DA                add     r11b, dl
      // 3C 1F                   cmp     al, 1Fh
      // $buf_add_cmp_1f = { 4? 02 ?? 4? 02 ?? 3? 1F }      removed due to 1 byte atom
      // B9 8D 10 B7 F8          mov     ecx, 0F8B7108Dh
      // E8 F1 BA FF FF          call    sub_140001280
      $hash_call_loadlib = { B? 8D 10 B7 F8 E8 }
      $hash_call_unk = { B? 91 B8 F6 88 E8 }
      
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($handshake, $err_xor_str) 
      and 1 of ($hash_call_*)
      or 2 of ($handshake, $err_xor_str)
} 

rule MAL_APT_NK_Andariel_Atharvan_3RAT {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the Atharvan 3RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9ff6998a-a2dd-5671-bd3f-ee69561f71ef"
   strings:
      $3RAT = "D:\\rang\\TOOL\\3RAT" 
      $atharvan = "Atharvan_dll.pdb"
   condition:
      uint16(0) == 0x5a4d 
      and 1 of them
}

rule MAL_APT_NK_Andariel_LilithRAT_Variant {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects a variant of the Lilith RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 80
      id = "916a289b-db7b-5f09-9d3e-589c3f09101d"
   strings:
      // I removed the 'wide' from the strings because the samples don't contain the strings
      // UTF-16 formatted and there's no indication that they ever will be, F.R.

      // The following are strings seen in the open source version of Lilith
      $lilith_1 = "Initiate a CMD session first." ascii
      $lilith_2 = "CMD is not open" ascii
      $lilith_3 = "Couldn't write command" ascii
      $lilith_4 = "Couldn't write to CMD: CMD not open" ascii

      // The following are strings that appear to be unique to the Unnamed Trojan based on Lilith
      $unique_1 = "Upload Error!" ascii
      $unique_2 = "ERROR: Downloading is already running!" ascii
      $unique_3 = "ERROR: Unable to open file:" ascii
      $unique_4 = "General error" ascii
      $unique_5 = "CMD error" ascii
      $unique_6 = "killing self" ascii
   condition:
      // I refactored the condition to make it more generic, F.R.
      uint16(0) == 0x5a4d 
      and filesize < 150KB 
      and ( 
         all of ($lilith_*) 
         or 4 of ($unique_*)
         or 1 of ($lilith_4, $unique_2) // both strings are very specific - let's use them as a unique indicator, F.R.
      ) 
}

rule MAL_APT_NK_Andariel_SocksTroy_Strings_OpCodes {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the SocksTroy malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9e7fb6ba-771e-5cae-a0d5-c0b95ee6d4e9"
   strings:
      $strHost = "-host" wide
      $strAuth = "-auth" wide
      $SocksTroy = "SocksTroy" 
      $cOpCodeCheck = { 81 E? A0 00 00 00 0F 84 ?? ?? ?? ?? 83 E? 03 74 ?? 83 E? 02 74 ?? 83 F? 0B }
   condition:
      uint16(0) == 0x5a4d and (
         1 of ($str*) 
         and all of ($c*) 
         or all of ($Socks*)
      )
}

rule MAL_APT_NK_Andariel_Agni {
   meta:
      author = "CISA.gov"
      description = "Detects samples of the Agni malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "ffe3f427-c10a-5ad4-ab29-c0d9b576c30f"
   strings:
      $xor = { 34 ?? 88 01 48 8D 49 01 0F B6 01 84 C0 75 F1 }
      $stackstrings = { C7 44 24 [5-10] C7 44 24 [5] C7 44 24 [5-10] C7 44 24 [5-10] C7 44 24 }
   condition:
      uint16(0) == 0x5a4d 
      and #xor > 100 
      and #stackstrings > 5
}

rule MAL_APT_NK_Andariel_GoLang_Validalpha_Handshake {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the GoLang Validalpha malware"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "51dafa43-9da0-569a-9123-7e9800284046"
   strings:
      $ = { 66 C7 00 AB CD C6 40 02 EF ?? 03 00 00 00 48 89 C1 ?? 03 00 00 00 }
   condition:
      all of them
}

rule MAL_APT_NK_Andariel_GoLang_Validalpha_Tasks {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the GoLang Validalpha malware"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "caa67a79-3ea6-5910-971c-f311722570ff"
   strings:
      $ = "main.ScreenMonitThread"
      $ = "main.CmdShell"
      $ = "main.GetAllFoldersAndFiles"
      $ = "main.SelfDelete"
   condition:
      all of them
}

rule MAL_APT_NK_Andariel_GoLang_Validalpha_BlackString {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the GoLang Validalpha malware based on a file path found in the samples"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 90
      id = "36f46a1d-69b6-5c99-9a54-6a14d62d2721"
   strings:
      $ = "I:/01___Tools/02__RAT/Black"
   condition:
      uint16(0) == 0x5A4D and all of them
}

/* yeah, YOLO ... triggers on a lot of stuff - we don't do that here to not freak out the users for no reason
rule MAL_APT_NK_INDICATOR_EXE_Packed_VMProtect {
        strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}

rule MAL_APT_NK_INDICATOR_EXE_Packed_Themida {
        strings:
        $s1 = ".themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}
*/

rule MAL_APT_NK_Andariel_ELF_Backdoor_Fipps {
   meta:
      author = "CISA.gov"
      description = "Detects a Linux backdoor named Fipps used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "040bca78-8b7e-5397-8a2b-1ddeed59eea3"
   strings:
      $a = "found mac address"
      $b = "RecvThread"
      $c = "OpenSSL-1.0.0-fipps"
      $d = "Disconnected!"
   condition:
      uint32(0) == 0x464c457f 
      and all of them
}

rule MAL_APT_NK_Andariel_BindShell {
   meta:
      author = "CISA.gov"
      description = "Detects a BindShell used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 70
      id = "3f6d83da-cea5-5e12-b0ba-93ace09d3d5c"
   strings:
      $str_comspec = "COMSPEC"
      $str_consolewindow = "GetConsoleWindow"
      $str_ShowWindow = "ShowWindow"
      $str_WSASocketA = "WSASocketA"
      $str_CreateProcessA = "CreateProcessA"
      $str_port = { B9 4D 05 00 00 89 }
   condition:
      uint16(0) == 0x5A4D 
      and all of them
}

rule MAL_APT_NK_Andariel_Grease2 {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the Grease2 malware family used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 80
      id = "4defbe08-b3c6-5ab9-9a57-cec57ff42d9a"
   strings:
      /* I bet this was an error and fixed the strings - I allow you to kick my butt when I'm wrong
      $str_rdpconf = "c: \\windows\\temp\\RDPConf.exe" fullword nocase
      $str_rdpwinst = "c: \\windows\\temp\\RDPWInst.exe" fullword nocase
      */
      $str_rdpconf = "emp\\RDPConf.exe"  // I removed the beginning of the string because the spaces looked like an error and I don't want to use nocase here, F.R.
      $str_rdpwinst = "emp\\RDPWInst.exe"
      $str_net_user = "net user"
      $str_admins_add = "net localgroup administrators"
   condition:
      uint16(0) == 0x5A4D and
      all of them
}

rule MAL_APT_NK_Andariel_NoPineapple_Dtrack_Unpacked {
   meta:
      author = "CISA.gov"
      description = "Detects the Dtrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "6ccaf24b-c110-5788-a792-fa7f39fb18f7"
   strings:
      $str_nopineapple = "< No Pineapple! >"
      $str_qt_library = "Qt 5.12.10"
      $str_xor = {8B 10 83 F6 ?? 83 FA 01 77}
   condition:
      uint16(0) == 0x5A4D
      and all of them
}

rule MAL_APT_NK_Andariel_DTrack_Unpacked {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects DTrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 75
      id = "0c161275-2b2e-51a4-9e08-c118fb4c8671"
   strings:
      $x_str_cmd_4 = "/c systeminfo > \"%s\" & tasklist > \"%s\" & netstat -naop tcp > \"%s\"" wide
      $x_str_cmd_2 = "/c ping -n 3 127.0.01 > NUL % echo EEE > \"%s\"" wide

      $str_mutex = "MTX_Global"
      $str_cmd_1 = "/c net use \\\\" wide
      $str_cmd_3 = "/c move /y %s \\\\" wide
   condition:
      // I changed the condition here because there are two strings which are highly specific and unique, F.R.
      uint16(0) == 0x5A4D
      and (
         1 of ($x*)
         or 3 of them
      )
}

rule MAL_APT_NK_Andariel_TigerRAT_Crowdsourced_Rule {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 75
      id = "6be65222-7d3c-5ff5-a9c7-d91dcf1deaa6"
   strings:
      $m1 = ".?AVModuleKeyLogger@@" fullword ascii
      $m2 = ".?AVModulePortForwarder@@" fullword ascii
      $m3 = ".?AVModuleScreenCapture@@" fullword ascii
      $m4 = ".?AVModuleShell@@" fullword ascii

      $s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
      $s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
      $s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
      $s4 = "del \"%s\"%s \"%s\" goto " ascii
      // $s5 = "[<<]" fullword ascii  // we don't need that short string and the rule probably doesn't lose anything without it, F.R.
   condition:
      uint16(0) == 0x5a4d and (
         all of ($s*) or (
            all of ($m*) and 1 of ($s*)
         ) 
         or (
            2 of ($m*) and 2 of ($s*)
         )
      )
}

rule MAL_APT_NK_WIN_Tiger_RAT_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "4579af62-52be-5f5f-a577-16ec50297c05"
    strings:
      $sequence_0 = { 33c0 89442438 89442430 448bcf 4533c0 }
         // n = 5, score = 200
         //   33c0                 | jmp                 5
         //   89442438             | dec                 eax
         //   89442430             | mov                 eax, ecx
         //   448bcf               | movzx               eax, byte ptr [eax]
         //   4533c0               | dec                 eax

      $sequence_1 = { 41b901000000 488bd6 488bcb e8???????? }
         // n = 4, score = 200
         //   41b901000000         | dec                 eax
         //   488bd6                | mov                 eax, dword ptr [ecx]
         //   488bcb               | jmp                 8
         //   e8????????           |                     

      $sequence_2 = { 4881ec90050000 8b01 8985c8040000 8b4104 }
         // n = 4, score = 200
         //   4881ec90050000       | test                eax, eax
         //   8b01                 | jns                 0x16
         //   8985c8040000         | dec                 eax
         //   8b4104               | mov                 eax, dword ptr [ecx]

      $sequence_3 = { 488b01 ff10 488b4f08 4c8d4c2430 }
         // n = 4, score = 200
         //   488b01               | mov                 edx, esi
         //   ff10                 | dec                 eax
         //   488b4f08             | mov                 ecx, ebx
         //   4c8d4c2430           | inc                 ecx

      $sequence_4 = { 488b01 ff10 488b4e18 488b01 }
         // n = 4, score = 200
         //   488b01               | dec                 eax
         //   ff10                 | cmp                 dword ptr [ecx + 0x18], 0x10
         //   488b4e18             | dec                 eax
         //   488b01               | sub                 esp, 0x590

      $sequence_5 = { 4881eca0000000 33c0 488bd9 488d4c2432 }
         // n = 4, score = 200
         //   4881eca0000000       | mov                 eax, dword ptr [ecx]
         //   33c0                 | mov                 dword ptr [ebp + 0x4c8], eax
         //   488bd9               | mov                 eax, dword ptr [ecx + 4]
         //   488d4c2432           | mov                 dword ptr [ebp + 0x4d0], eax

      $sequence_6 = { 488b01 eb03 488bc1 0fb600 }
         // n = 4, score = 200
         //   488b01               | inc                 ecx
         //   eb03                 | mov                 ebx, dword ptr [ebp + ebp]
         //   488bc1               | inc                 ecx
         //   0fb600               | movups              xmmword ptr [edi], xmm0

      $sequence_7 = { 488b01 8b10 895124 448b4124 4585c0 }
         // n = 5, score = 200
         //   488b01               | sub                 esp, 0x30
         //   8b10                 | dec                 ecx
         //   895124               | mov                 ebx, eax
         //   448b4124             | dec                 eax
         //   4585c0               | mov                 ecx, eax

      $sequence_8 = { 4c8d0d31eb0000 c1e918 c1e808 41bf00000080 }
         // n = 4, score = 100
         //   4c8d0d31eb0000       | jne                 0x1e6
         //   c1e918               | dec                 eax
         //   c1e808               | lea                 ecx, [0xbda0]
         //   41bf00000080         | dec                 esp

      $sequence_9 = { 488bd8 4885c0 752d ff15???????? 83f857 0f85e0010000 488d0da0bd0000 }
         // n = 7, score = 100
         //   488bd8               | dec                 eax
         //   4885c0               | mov                 ebx, eax
         //   752d                 | dec                 eax
         //   ff15????????         |                     
         //   83f857               | test                eax, eax
         //   0f85e0010000         | jne                 0x2f
         //   488d0da0bd0000       | cmp                  eax, 0x57

      $sequence_10 = { 75d4 488d1d7f6c0100 488b4bf8 4885c9 740b }
         // n = 5, score = 100
         //   75d4                 | lea                 ecx, [0xeb31]
         //   488d1d7f6c0100       | shr                 ecx, 0x18
         //   488b4bf8             | shr                 eax, 8
         //   4885c9               | inc                 ecx
         //   740b                 | mov                 edi, 0x80000000

      $sequence_11 = { 0f85d9000000 488d15d0c90000 41b810200100 488bcd e8???????? eb6b b9f4ffffff }
         // n = 7, score = 100
         //   0f85d9000000         | jne                 0xffffffd6
         //   488d15d0c90000       | dec                 eax
         //   41b810200100         | lea                 ebx, [0x16c7f]
         //   488bcd               | dec                 eax
         //   e8????????           |                     
         //   eb6b                 | mov                 ecx, dword ptr [ebx - 8]
         //   b9f4ffffff           | dec                 eax

      $sequence_12 = { 48890d???????? 488905???????? 488d05ae610000 488905???????? 488d05a0550000 488905???????? }
         // n = 6, score = 100
         //    48890d????????       |                     
         //   488905????????       |                     
         //   488d05ae610000       | test                ecx, ecx
         //   488905????????       |                     
         //   488d05a0550000       | je                  0x10
         //   488905????????       |                     

      $sequence_13 = { 8bcf e8???????? 488b7c2448 85c0 0f8440030000 488d0560250100 }
         // n = 6, score = 100
         //   8bcf                  | mov                 eax, 0x12010
         //   e8????????           |                     
         //   488b7c2448           | dec                 eax
         //   85c0                 | mov                 ecx, ebp
         //   0f8440030000         | jmp                 0x83
         //   488d0560250100       | mov                 ecx, 0xfffffff4

      $sequence_14 = { ff15???????? 8b05???????? 2305???????? ba02000000 33c9 8905???????? 8b05???????? }
         // n = 7, score = 100
         //   ff15????????         |                     
         //   8b05????????         |                     
         //   2305????????         |                     
         //   ba02000000           | dec                 eax
         //   33c9                 | lea                 eax, [0x61ae]
         //   8905????????         |                     
         //   8b05????????         |                     

      $sequence_15 = { 4883ec30 498bd8 e8???????? 488bc8 4885c0 }
         // n = 5, score = 100
         //   4883ec30             | jne                 0xdf
         //   498bd8               | dec                 eax
         //   e8????????           |                     
         //   488bc8               | lea                 edx, [0xc9d0]
         //   4885c0               | inc                 ecx

    condition:
        filesize < 600KB and 7 of them
}

rule MAL_APT_NK_WIN_DTrack_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects DTrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "1b40c685-beba-50fa-b484-c1526577cb23"
   strings:
      $sequence_0 = { 52 8b4508 50 e8???????? 83c414 8b4d10 51 }
         // n = 7, score = 400
         //   52                   | push                edx
         //   8b4508               | mov                 eax, dword ptr [ebp + 8]
         //   50                   | push                eax
         //   e8????????           |                     
         //   83c414               | add                 esp, 0x14
         //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
         //   51                   | push                ecx

      $sequence_1 = { 3a4101 7523 83854cf6ffff02 838550f6ffff02 80bd4af6ffff00 75ae c78544f6ffff00000000 }
         // n = 7, score = 300
         //   3a4101               | cmp                 al, byte ptr [ecx + 1]
         //    7523                 | jne                 0x25
         //   83854cf6ffff02       | add                 dword ptr [ebp - 0x9b4], 2
         //   838550f6ffff02       | add                 dword ptr [ebp - 0x9b0], 2
         //   80bd4af6ffff00       | cmp                 byte ptr [ebp - 0x9b6], 0
         //   75ae                 | jne                 0xffffffb0
         //   c78544f6ffff00000000     | mov     dword ptr [ebp - 0x9bc], 0

      $sequence_2 = { 50 ff15???????? a3???????? 68???????? e8???????? 83c404 50 }
         // n = 7, score = 300
         //   50                   | push                eax
         //   ff15????????         |                     
         //   a3????????           |                     
         //   68????????           |                     
         //   e8????????           |                     
         //   83c404               | add                 esp, 4
         //   50                   | push                eax

      $sequence_3 = { 8d8dd4faffff 51 e8???????? 83c408 8b15???????? }
         // n = 5, score = 300
         //   8d8dd4faffff         | lea                 ecx, [ebp - 0x52c]
         //   51                   | push                ecx
         //   e8????????           |                     
         //   83c408               | add                 esp, 8
         //   8b15????????         |                     

      $sequence_4 = { 8855f5 6a5c 8b450c 50 e8???????? }
         // n = 5, score = 300
         //   8855f5               | mov                 byte ptr [ebp - 0xb], dl
         //   6a5c                 | push                0x5c
         //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
         //   50                   | push                eax
         //   e8????????           |                     

      $sequence_5 = { 51 e8???????? 83c410 8b558c 52 }
         // n = 5, score = 300
         //   51                   | push                ecx
         //   e8????????           |                     
         //   83c410               | add                 esp, 0x10
         //   8b558c                | mov                 edx, dword ptr [ebp - 0x74]
         //   52                   | push                edx

      $sequence_6 = { 8b4d0c 51 68???????? 8d9560eaffff 52 e8???????? }
         // n = 6, score = 300
         //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
         //   51                   | push                ecx
         //   68????????           |                     
         //   8d9560eaffff         | lea                 edx, [ebp - 0x15a0]
         //   52                   | push                edx
         //   e8????????           |                     

      $sequence_7 = { 83c001 8945f4 837df420 7d2c 8b4df8 }
         // n = 5, score = 300
         //   83c001               | add                 eax, 1
         //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
         //   837df420             | cmp                 dword ptr [ebp - 0xc], 0x20
         //   7d2c                 | jge                 0x2e
         //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

      $sequence_8 = { 83c001 89856cf6ffff 8b8d70f6ffff 8a11 }
         // n = 4, score = 300
         //   83c001               | add                 eax, 1
         //   89856cf6ffff         | mov                 dword ptr [ebp - 0x994], eax
         //   8b8d70f6ffff         | mov                 ecx, dword ptr [ebp - 0x990]
         //   8a11                 | mov                 dl, byte ptr [ecx]

      $sequence_9 = { 0355f0 0fb602 0fb64df7 33c1 0fb655fc 33c2 }
         // n = 6, score = 200
         //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
         //   0fb602               | movzx               eax, byte ptr [edx]
         //   0fb64df7             | movzx               ecx, byte ptr [ebp - 9]
         //   33c1                 | xor                 eax, ecx
         //    0fb655fc             | movzx               edx, byte ptr [ebp - 4]
         //   33c2                 | xor                 eax, edx

      $sequence_10 = { d1e9 894df8 8b5518 8955fc c745f000000000 }
         // n = 5, score = 200
         //   d1e9                 | shr                 ecx, 1
         //   894df8               | mov                 dword ptr [ebp - 8], ecx
         //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
         //   8955fc               | mov                 dword ptr [ebp - 4], edx
         //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0

      $sequence_11 = { 8b4df0 3b4d10 0f8d90000000 8b5508 0355f0 0fb602 }
         // n = 6, score = 200
         //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
         //   3b4d10               | cmp                 ecx, dword ptr [ebp + 0x10]
         //   0f8d90000000         | jge                 0x96
         //   8b5508               | mov                 edx, dword ptr [ebp + 8]
         //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
         //   0fb602               | movzx               eax, byte ptr [edx]

      $sequence_12 = { 894d14 8b45f8 c1e018 8b4dfc c1e908 0bc1 }
         // n = 6, score = 200
         //   894d14               | mov                 dword ptr [ebp + 0x14], ecx
         //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
         //   c1e018               | shl                 eax, 0x18
         //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
         //   c1e908               | shr                 ecx, 8
         //   0bc1                 | or                  eax, ecx

      $sequence_13 = { 0bc1 894518 8b5514 8955f8 }
         // n = 4, score = 200
         //   0bc1                 | or                  eax, ecx
         //   894518               | mov                 dword ptr [ebp + 0x18], eax
         //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
         //   8955f8               | mov                 dword ptr [ebp - 8], edx

      $sequence_14 = { 8b5514 8955f8 8b4518 8945fc e9???????? 8be5 }
         // n = 6, score = 200
         //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
         //   8955f8               | mov                 dword ptr [ebp - 8], edx
         //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
         //   8945fc               | mov                 dword ptr [ebp - 4], eax
         //   e9????????           |                     
         //   8be5                 | mov                 esp, ebp

   condition:
      filesize < 1700KB and 7 of them
}

