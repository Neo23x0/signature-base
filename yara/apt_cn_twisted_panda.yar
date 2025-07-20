rule APT_CN_TwistedPanda_loader {
   meta:
      author = "Check Point Research"
      description = "Detects loader used by TwistedPanda"
      date = "2022-04-14"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      score = 80
      hash1 = "5b558c5fcbed8544cb100bd3db3c04a70dca02eec6fedffd5e3dcecb0b04fba0"
      hash2 = "efa754450f199caae204ca387976e197d95cdc7e83641444c1a5a91b58ba6198"
      
      id = "a10f6019-f069-579c-b112-18537a7d8fd8"
   strings:
      
      // 6A 40                                   push    40h ; '@'
      // 68 00 30 00 00                          push    3000h
      $seq1 = { 6A 40 68 00 30 00 00 }
      
      // 6A 00                                   push    0               ; lpOverlapped
      // 50                                      push    eax             ; lpNumberOfBytesRead
      // 6A 14                                   push    14h             ; nNumberOfBytesToRead
      // 8D ?? ?? ?? ?? ??                       lea     eax, [ebp+Buffer]
      // 50                                      push    eax             ; lpBuffer
        // 53                                      push    ebx             ; hFile
      // FF 15 04 D0 4C 70                       call    ds:ReadFile
      $seq2 = { 6A 00 50 6A 14 8D ?? ?? ?? ?? ?? 50 53 FF }
      // 6A 00                                   push    0
      // 6A 00                                   push    0
      // 6A 03                                   push    3
      // 6A 00                                   push    0
      // 6A 03                                   push    3
      // 68 00 00 00 80                          push    80000000h
      $seq3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 80 }
            
      // Decryption sequence
      $decryption = { 8B C? [2-3] F6 D? 1A C? [4-6] 30 0? ?? 4? }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB and all of ($seq*) and $decryption
}

rule APT_CN_TwistedPanda_SPINNER_1 {
   meta:
      author = "Check Point Research"
      description = "Detects the obfuscated variant of SPINNER payload used by TwistedPanda"
      date = "2022-04-14"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      score = 80
      hash1 = "a9fb7bb40de8508606a318866e0e5ff79b98f314e782f26c7044622939dfde81"
      
      id = "0b44013d-0caa-5ea2-ab08-e2a6a5732c03"
   strings:
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C6                                                  mov     byte ptr [eax], 0
      $config_init = { C7 ?? ?? ?? 00 00 00 C7 ?? ?? ?? 00 00 00 C6 }
      $c2_cmd_1 = { 01 00 03 10}
      $c2_cmd_2 = { 02 00 01 10}
      $c2_cmd_3 = { 01 00 01 10}
      // 8D 83 ?? ?? ?? ??                                   lea     eax, xor_key[ebx]
      // 80 B3 ?? ?? ?? ?? ??                                xor     xor_key[ebx], 50h
      // 89 F1                                               mov     ecx, esi        ; this
      // 6A 01                                               push    1               ; Size
      // 50                                                  push    eax             ; Src
      // E8 ?? ?? ?? ??                                      call    str_append
      // 80 B3 ?? ?? ?? ?? ??                                xor     xor_key[ebx], 50h
      $decryption = { 8D 83 [4] 80 B3 [5] 89 F1 6A 01 50 E8 [4] 80 B3 }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #config_init > 10 and 2 of ($c2_cmd_*) and $decryption
}

rule APT_CN_TwistedPanda_SPINNER_2 {
   meta:
      author = "Check Point Research"
      description = "Detects an older variant of SPINNER payload used by TwistedPanda"
      date = "2022-04-14"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      score = 80
      hash1 = "28ecd1127bac08759d018787484b1bd16213809a2cc414514dc1ea87eb4c5ab8"
      
      id = "bbbf3af1-127f-5d32-967f-bdb94311d1d6"
   strings:
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C6                                                  mov     byte ptr [eax], 0
      $config_init = { C7 [3] 00 00 00 C7 [3] 00 00 00 C6 }
      $c2_cmd_1 = { 01 00 03 10 }
      $c2_cmd_2 = { 02 00 01 10 }
      $c2_cmd_3 = { 01 00 01 10 }
      $c2_cmd_4 = { 01 00 00 10 }
      $c2_cmd_5 = { 02 00 00 10 }
      // 80 B3 ?? ?? ?? ?? ??                    xor     ds:dd_encrypted_url[ebx], 50h
      // 8D BB ?? ?? ?? ??                       lea     edi, dd_encrypted_url[ebx]
      // 8B 56 14                                mov     edx, [esi+14h]
      // 8B C2                                   mov     eax, edx
      // 8B 4E 10                                mov     ecx, [esi+10h]
      // 2B C1                                   sub     eax, ecx
      // 83 F8 01                                cmp     eax, 1
      $decryption = { 80 B3 [5] 8D BB [4] 8B 56 14 8B C2 8B 4E 10 2B C1 83 F8 01 }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #config_init > 10 and 2 of ($c2_cmd_*) and $decryption
}

rule APT_CN_TwistedPanda_64bit_Loader {
   meta:
      author = "Check Point Research"
      description = "Detects the 64bit Loader DLL used by TwistedPanda"
      date = "2022-04-14"      
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      score = 80
      hash1 = "e0d4ef7190ff50e6ad2a2403c87cc37254498e8cc5a3b2b8798983b1b3cdc94f"
      
      id = "2172dd33-204b-5a05-ad26-534a0c1d7a17"
   strings:
      // 48 8D ?? ?? ?? ?? ?? ?? ??              lea     rdx, ds:2[rdx*2]
      // 48 8B C1                                mov     rax, rcx
      // 48 81 ?? ?? ?? ?? ??                    cmp     rdx, 1000h
      // 72 ??                                   jb      short loc_7FFDF0BA1B48
      $path_check = { 48 8D [6] 48 8B ?? 48 81 [5] 72 }
      // 48 8B D0                                mov     rdx, rax        ; lpBuffer
      // 41 B8 F0 16 00 00                       mov     r8d, 16F0h      ; nNumberOfBytesToRead
      // 48 8B CF                                mov     rcx, rdi        ; hFile
      // 48 8B D8                                mov     rbx, rax
      // FF ?? ?? ?? ??                          call    cs:ReadFile
      $shellcode_read = { 48 8B D0 41 B8 F0 16 00 00 48 8B CF 48 8B D8 FF} 
      // BA F0 16 00 00                          mov     edx, 16F0h      ; dwSize
      // 44 8D 4E 40                             lea     r9d, [rsi+40h]  ; flProtect
      // 33 C9                                   xor     ecx, ecx        ; lpAddress
      // 41 B8 00 30 00 00                       mov     r8d, 3000h      ; flAllocationType
      // FF ?? ?? ?? ?? ??                       call    cs:VirtualAlloc
     $shellcode_allocate = { BA F0 16 00 00 44 8D 4E 40 33 C9 41 B8 00 30 00 00 FF }
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and $path_check and $shellcode_allocate and $shellcode_read
}

rule APT_CN_TwistedPanda_droppers {
   meta:
      author = "Check Point Research"
      description = "Detects droppers used by TwistedPanda"
      date = "2022-04-14"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      score = 80
      hash1 = "59dea38da6e515af45d6df68f8959601e2bbf0302e35b7989e741e9aba2f0291"
      hash2 = "8b04479fdf22892cdfebd6e6fbed180701e036806ed0ddbe79f0b29f73449248"
      hash3 = "f29a0cda6e56fc0e26efa3b6628c6bcaa0819a3275a10e9da2a8517778152d66"
      
      id = "f61c8b97-5870-5837-942f-f1650870960a"
   strings:
     // 81 FA ?? ?? ?? ??                                   cmp     edx, 4BED1896h
     // 75 ??                                               jnz     short loc_140001829
     // E8 ?? ?? ?? ??                                      call    sub_1400019D0
     // 48 89 05 ?? ?? ?? ??                                mov     cs:qword_14001ED38, rax
     // E? ?? ?? ?? ??                                      jmp     loc_1400018DD
      $switch_control = { 81 FA [4] 75 ?? E8 [4] 48 89 05 [4] E? }
     // 41 0F ?? ??                                         movsx   edx, byte ptr [r9]
     // 44 ?? ??                                            or      r8d, edx
     // 41 ?? ?? 03                                         rol     r8d, 3
     // 41 81 ?? ?? ?? ?? ??                                xor     r8d, 0EF112233h
     // 41 ?? ??                                            mov     eax, r10d
      $byte_manipulation = { 41 0F [2] 44 [2] 41 [2] 03 41 81 [5] 41 }
     // %public%
     $stack_strings_1 = { 25 00 70 00 }
     $stack_strings_2 = { 75 00 62 00 }
     $stack_strings_3 = { 6C 00 69 00 }
     $stack_strings_4 = { 63 00 25 00 }
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #switch_control > 8 and all of ($stack_strings_*) and $byte_manipulation
}
