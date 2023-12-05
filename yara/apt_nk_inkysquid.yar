/* 
Copyright 2021 by Volexity, Inc.

The 2-Clause BSD License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule APT_RUBY_RokRat_Loader : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "Ruby loader seen loading the ROKRAT malware family."
        date = "2021-06-22"
        hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
        license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        id = "69d09560-a769-55d3-a442-e37f10453cde"
    strings:
        $magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
        $magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
        $magic3 = "firoffset..scupd.size" ascii wide
        $magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
        
        // Original: 'Fiddle::Pointer' (Reversed)
        $s1 = "clRnbp9GU6oTZsRGZpZ"
        $s2 = "RmlkZGxlOjpQb2ludGVy"
        $s3 = "yVGdul2bQpjOlxGZklmR"
        $s4 = "XZ05WavBlO6UGbkRWaG"

    condition:
        any of ($magic*) or
        any of ($s*)
}

rule APT_PY_BlueLight_Loader : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "Python Loader used to execute the BLUELIGHT malware family."
        date = "2021-06-22"
        hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
        license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        id = "f8da3e40-c3b0-5b7f-8ece-81874993d8cd"
    strings:
        $s1 = "\"\".join(chr(ord(" ascii
        $s2 = "import ctypes " ascii
        $s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
        $s4 = "ctypes.memmove" ascii
        $s5 = "python ended" ascii

    condition:
        all of them
}

/* slightly modified for performance reasons by Florian Roth */
rule APT_MAL_Win_DecRok : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
        hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
        license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        id = "dc83843d-fd2a-52f1-82e8-8e36b135a0c5"
    strings:
        $v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}

        $av1 = "Select * From AntiVirusProduct" wide
        $av2 = "root\\SecurityCenter2" wide

      /* CreateThread..%02x */
        $funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

    condition:
        all of them
}

rule APT_MAL_Win_RokLoad_Loader : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "A shellcode loader used to decrypt and run an embedded executable."
        hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
        license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        id = "229dbf3c-1538-5ecd-b5f8-8c9a9c81c515"
    strings:
        $bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }
    
    condition:
        $bytes00 at 0
}


/* rules by S2W */

rule APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine {
     meta:
       author        = "S2WLAB_TALON_JACK2"
       description   = "Detects Ruby ShellCode XOR routine used by ScarCruft APT group"
       type          = "APT"
       version       = "0.1"
       date          = "2021-05-20"
       reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
       id = "c393f2db-8ade-5083-9cec-f62f23056f8b"
     strings:
         /*
         8B 4C 18 08             mov     ecx, [eax+ebx+8]
         C1 C7 0D                rol     edi, 0Dh
         40                      inc     eax
         F6 C7 01                test    bh, 1
         74 06                   jz      short loc_D0
         81 F7 97 EA AE 78       xor     edi, 78AEEA97h
         */
         $hex1   = {C1 C7 0D 40 F6 C7 01 74 ?? 81 F7}
         /*
         41 C1 C2 0D             rol     r10d, 0Dh
         41 8B C2                mov     eax, r10d
         44 8B CA                mov     r9d, edx
         41 8B CA                mov     ecx, r10d
         41 81 F2 97 EA AE 78    xor     r10d, 78AEEA97h
         */
         $hex2   = {41 C1 C2 0D 41 8B C2 44 8B CA 41 8B CA 41 81 F2}
     condition:
         1 of them
 }

rule APT_NK_Scarcruft_evolved_ROKRAT {
    meta:
        author        = "S2WLAB_TALON_JACK2"
        description   = "Detects RokRAT malware used by ScarCruft APT group"
        type          = "APT"
        version       = "0.1"
        date          = "2021-07-09"
        reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
        id = "53cabf41-0154-5372-b667-60d8a7cb9806"
    strings:
/*
0x140130f25 C744242032311223              mov dword ptr [rsp + 0x20], 0x23123132
0x140130f2d C744242434455667              mov dword ptr [rsp + 0x24], 0x67564534
0x140130f35 C744242878899AAB              mov dword ptr [rsp + 0x28], 0xab9a8978
0x140130f3d C744242C0CBDCEDF              mov dword ptr [rsp + 0x2c], 0xdfcebd0c
0x140130f45 C745F02B7EA516                mov dword ptr [rbp - 0x10], 0x16a57e2b
0x140130f4c C745F428AED2A6                mov dword ptr [rbp - 0xc], 0xa6d2ae28
0x140130f53 C745F8ABF71588                mov dword ptr [rbp - 8], 0x8815f7ab
0x140130f5a C745FC09CF4F3C                mov dword ptr [rbp - 4], 0x3c4fcf09
*/
        $AES_IV_KEY = {
        C7 44 24 ?? 32 31 12 23
        C7 44 24 ?? 34 45 56 67
        C7 44 24 ?? 78 89 9A AB
        C7 44 24 ?? 0C BD CE DF
        C7 45 ?? 2B 7E A5 16
        C7 45 ?? 28 AE D2 A6
        C7 45 ?? AB F7 15 88
        C7 45 ?? 09 CF 4F 3C
        }
/*
0x14012b637 80E90F                        sub cl, 0xf
0x14012b63a 80F1C8                        xor cl, 0xc8
0x14012b63d 8848FF                        mov byte ptr [rax - 1], cl
0x14012b640 4883EA01                      sub rdx, 1
*/
       $url_deocde = {
               80 E9 0F
               80 F1 C8
               88 48 ??
               48 83 EA 01  }
    condition:
        uint16(0) == 0x5A4D and
        any of them
}
