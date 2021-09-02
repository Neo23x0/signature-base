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
    strings:
        $v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}

        $av1 = "Select * From AntiVirusProduct" wide
        $av2 = "root\\SecurityCenter2" wide

      /* CreateThread..%02x */
        $funcformat = { 43 72 65 61 74 65 54 68 72 65 61 64 [0-10] 25 30 32 78 }

    condition:
        all of them and $funcformat
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
    strings:
        $bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }
    
    condition:
        $bytes00 at 0
}
