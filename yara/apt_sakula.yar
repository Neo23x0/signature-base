rule malware_sakula_xorloop {
  meta:
    description = "XOR loops from Sakula malware"
    author = "David Cannings"
    md5 = "fc6497fe708dbda9355139721b6181e7"

  strings:
    $mz = "MZ"

    // XOR decode loop (non-null, non-key byte only)
    $opcodes_decode_loop01 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }

    // XOR decode
    $opcodes_decode_loop02 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }

  condition:
    $mz at 0 and any of ($opcodes*)
}

rule malware_sakula_memory {
  meta:
    description = "Sakula malware - strings after unpacking (memory rule)"
    author = "David Cannings"
    md5 = "b3852b9e7f2b8954be447121bb6b65c3"

  strings:
    $str01 = "cmd.exe /c ping 127.0.0.1 & del \"%s\""
    $str02 = "cmd.exe /c rundll32 \"%s\" Play \"%s\""
    $str03 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
    $str04 = "cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c \"%s\""
    $str05 = "Self Process Id:%d"
    $str06 = "%d_%d_%d_%s"
    $str07 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
    $str08 = "cmd.exe /c rundll32 \"%s\" ActiveQvaw \"%s\""

    // Encode loop, operations: rol 1; xor ??;
    $opcodes01 = { 83 F9 00 74 0E 31 C0 8A 03 D0 C0 34 ?? 88 03 49 43 EB ED }

    // Encode loop, single byte XOR
    $opcodes02 = { 31 C0 8A 04 13 32 01 83 F8 00 75 0E 83 FA 00 74 04 49 4A }

  condition:
    4 of them
}

rule malware_sakula_shellcode {
  meta:
    description = "Sakula shellcode - taken from decoded setup.msi but may not be unique enough to identify Sakula"
    author = "David Cannings"

  strings:
    /*
      55                      push    ebp
      89 E5                   mov     ebp, esp
      E8 00 00 00 00          call    $+5
      58                      pop     eax
      83 C0 06                add     eax, 6
      C9                      leave
      C3                      retn
    */
    // Get EIP technique (may not be unique enough to identify Sakula)
    // Note this only appears in memory or decoded files
    $opcodes01 = { 55 89 E5 E8 00 00 00 00 58 83 C0 06 C9 C3 }

    /*
      8B 5E 3C                mov     ebx, [esi+3Ch]  ; Offset to PE header
      8B 5C 1E 78             mov     ebx, [esi+ebx+78h] ; Length of headers
      8B 4C 1E 20             mov     ecx, [esi+ebx+20h] ; Number of data directories
      53                      push    ebx
      8B 5C 1E 24             mov     ebx, [esi+ebx+24h] ; Export table
      01 F3                   add     ebx, esi
    */
    // Export parser
    $opcodes02 = { 8B 5E 3C 8B 5C 1E 78 8B 4C 1E 20 53 8B 5C 1E 24 01 F3 }

  condition:
    any of them
}
