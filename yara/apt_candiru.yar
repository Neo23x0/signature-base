import "pe"

rule MAL_DevilsTongue_HijackDll {
   meta:
      description = "Detects SOURGUM's DevilsTongue hijack DLL"
      author = "Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-07-15"
      reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
      score = 80
      id = "390b8b73-6740-513d-8c70-c9002be0ce69"
   strings:
      $str1 = "windows.old\\windows" wide
      $str2 = "NtQueryInformationThread"
      $str3 = "dbgHelp.dll" wide
      $str4 = "StackWalk64"
      $str5 = "ConvertSidToStringSidW"
      $str6 = "S-1-5-18" wide
      $str7 = "SMNew.dll" // DLL original name
      // Call check in stack manipulation
      // B8 FF 15 00 00   mov     eax, 15FFh
      // 66 39 41 FA      cmp     [rcx-6], ax
      // 74 06            jz      short loc_1800042B9
      // 80 79 FB E8      cmp     byte ptr [rcx-5], 0E8h ;
      $code1 = { B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8 }
      // PRNG to generate number of times to sleep 1s before exiting
      // 44 8B C0 mov r8d, eax
      // B8 B5 81 4E 1B mov eax, 1B4E81B5h
      // 41 F7 E8 imul r8d
      // C1 FA 05 sar edx, 5
      // 8B CA    mov ecx, edx
      // C1 E9 1F shr ecx, 1Fh
      // 03 D1    add edx, ecx
      // 69 CA 2C 01 00 00 imul ecx, edx, 12Ch
      // 44 2B C1 sub r8d, ecx
      // 45 85 C0 test r8d, r8d
      // 7E 19    jle  short loc_1800014D0
      $code2 = { 44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19 }
   condition:
      filesize < 800KB and
      uint16(0) == 0x5A4D and
      ( pe.characteristics & pe.DLL ) and
      (
         4 of them or
         ( $code1 and $code2 ) or
         pe.imphash() == "9a964e810949704ff7b4a393d9adda60"
      )
}
