rule Octowave_Loader_03_2025 {
    meta:
        description = "Detects opcodes found in Octowave loader DLLs and WAV steganography files"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-19"
		  score = 75
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        hash1 = "0504BFBACB6E10B81196F625F2FE37B33500E7BF65FD82D3510A2B178C6CD5BD"
        hash2 = "3A2DB0CB9EE01549A6B660D58115D112D36A744D65705394B54D7D95287C7A74"
        hash3 = "EB50D06057FE123D6E9F7A76D3D1A4BC5307E8F15D017BE8F6031E92136CF36A"
        hash4 = "24715920E749B014BA05F74C96627A27355C5860A14461C106AA48A7ABA371EA"
        shoutout = "https://yaratoolkit.securitybreak.io/"
        id = "d583c416-be20-5fcf-848e-edd037e3b0d4"
	/*
	0x5bb1d 55                            push ebp
	0x5bb1e 8BEC                          mov ebp, esp
	0x5bb20 56                            push esi
	0x5bb21 57                            push edi
	0x5bb22 8BD1                          mov edx, ecx
	0x5bb24 33C0                          xor eax, eax
	0x5bb26 8BFA                          mov edi, edx
	0x5bb28 6A06                          push 6
	0x5bb2a 59                            pop ecx
	0x5bb2b AB                            stosd dword ptr es:[edi], eax
	0x5bb2c AB                            stosd dword ptr es:[edi], eax
	0x5bb2d AB                            stosd dword ptr es:[edi], eax
	0x5bb2e AB                            stosd dword ptr es:[edi], eax
	0x5bb2f 8B4508                        mov eax, dword ptr [ebp + 8]
	0x5bb32 8BFA                          mov edi, edx
	0x5bb34 83621000                      and dword ptr [edx + 10h], 0
	0x5bb38 8BF0                          mov esi, eax
	0x5bb3a 83621400                      and dword ptr [edx + 14h], 0
	0x5bb3e F3A5                          rep movsd dword ptr es:[edi], dword ptr [esi]
	0x5bb40 83601000                      and dword ptr [eax + 10h], 0
	 */
	strings:
		$opcode_1 = {
			55
			8B EC
			56
			57
			8B D1
			33 C0
			8B FA
			6A 06
			59
			AB
			AB
			AB
			AB
			8B 45 08
			8B FA
			83 62 10 00
			8B F0
			83 62 14 00
			F3 A5
			83 60 10 00
		}
	/*
	0x3a6d 55                            push ebp
	0x3a6e 8BEC                          mov ebp, esp
	0x3a70 8B550C                        mov edx, dword ptr [ebp + 0ch]
	0x3a73 56                            push esi
	0x3a74 8BF1                          mov esi, ecx
	0x3a76 8B4614                        mov eax, dword ptr [esi + 14h]
	0x3a79 8B4E10                        mov ecx, dword ptr [esi + 10h]
	0x3a7c 2BC1                          sub eax, ecx
	0x3a7e 3BD0                          cmp edx, eax
	0x3a80 7731                          ja 3ab3h
	0x3a82 837E1407                      cmp dword ptr [esi + 14h], 7
	0x3a86 53                            push ebx
	0x3a87 8D1C11                        lea ebx, [ecx + edx]
	0x3a8a 57                            push edi
	0x3a8b 895E10                        mov dword ptr [esi + 10h], ebx
	0x3a8e 8BFE                          mov edi, esi
	0x3a90 7602                          jbe 3a94h
	0x3a92 8B3E                          mov edi, dword ptr [esi]
	0x3a94 8D0412                        lea eax, [edx + edx]
	0x3a97 50                            push eax
	0x3a98 FF7508                        push dword ptr [ebp + 8]
	0x3a9b 8D0C4F                        lea ecx, [edi + ecx*2]
	0x3a9e 51                            push ecx
	0x3a9f E89C9B1100                    call 11d640h
	0x3aa4 83C40C                        add esp, 0ch
	0x3aa7 33C0                          xor eax, eax
	0x3aa9 6689045F                      mov word ptr [edi + ebx*2], ax
	0x3aad 8BC6                          mov eax, esi
	0x3aaf 5F                            pop edi
	0x3ab0 5B                            pop ebx
	0x3ab1 EB0F                          jmp 3ac2h
	0x3ab3 52                            push edx
	0x3ab4 FF7508                        push dword ptr [ebp + 8]
	0x3ab7 8BCE                          mov ecx, esi
	0x3ab9 FF7508                        push dword ptr [ebp + 8]
	0x3abc 52                            push edx
	0x3abd E8FF040000                    call 3fc1h
	0x3ac2 5E                            pop esi
	0x3ac3 5D                            pop ebp
	0x3ac4 C20800                        ret 8
	 */
		$opcode_2 = {
			55
			8B EC
			8B 55 ??
			56
			8B F1
			8B 46 ??
			8B 4E ??
			2B C1
			3B D0
			77 ??
			83 7E ?? 07
			53
			8D 1C 11
			57
			89 5E ??
			8B FE
			76 ??
			8B 3E
			8D 04 12
			50
			FF 75 ??
			8D 0C 4F
			51
			E8 ?? ?? ?? ??
			83 C4 0C
			33 C0
			66 89 04 5F
			8B C6
			5F
			5B
			EB ??
			52
			FF 75 ??
			8B CE
			FF 75 ??
			52
			E8 ?? ?? ?? ??
			5E
			5D
			C2 08 00
		}

	/*
	0x4446 55                            push ebp
	0x4447 8BEC                          mov ebp, esp
	0x4449 8B4D08                        mov ecx, dword ptr [ebp + 8]
	0x444c 83C90F                        or ecx, 0fh
	0x444f 56                            push esi
	0x4450 3B4D10                        cmp ecx, dword ptr [ebp + 10h]
	0x4453 771C                          ja 4471h
	0x4455 8B750C                        mov esi, dword ptr [ebp + 0ch]
	0x4458 8BD6                          mov edx, esi
	0x445a 8B4510                        mov eax, dword ptr [ebp + 10h]
	0x445d D1EA                          shr edx, 1
	0x445f 2BC2                          sub eax, edx
	0x4461 3BF0                          cmp esi, eax
	0x4463 770C                          ja 4471h
	0x4465 8D0432                        lea eax, [edx + esi]
	0x4468 3BC8                          cmp ecx, eax
	0x446a 0F42C8                        cmovb ecx, eax
	0x446d 8BC1                          mov eax, ecx
	0x446f EB03                          jmp 4474h
	 */
		$opcode_3 = {
			55
			8B EC
			8B 4D 08
			83 C9 ??
			56
			3B 4D 10
			77 1C
			8B 75 0C
			8B D6
			8B 45 10
			D1 EA
			2B C2
			3B F0
			77 0C
			8D 04 32
			3B C8
			0F 42 C8
			8B C1
			EB 03
		}

	/*
	0x3cf6 56                            push esi
	0x3cf7 8BF1                          mov esi, ecx
	0x3cf9 8B4614                        mov eax, dword ptr [esi + 14h]
	0x3cfc 83F807                        cmp eax, 7
	0x3cff 7611                          jbe 3d12h
	0x3d01 8D044502000000                lea eax, [eax*2 + 2]
	0x3d08 50                            push eax
	0x3d09 FF36                          push dword ptr [esi]
	0x3d0b E8F4050000                    call 4304h
	0x3d10 59                            pop ecx
	0x3d11 59                            pop ecx
	0x3d12 83661000                      and dword ptr [esi + 10h], 0
	0x3d16 33C0                          xor eax, eax
	0x3d18 C7461407000000                mov dword ptr [esi + 14h], 7
	0x3d1f 668906                        mov word ptr [esi], ax
	0x3d22 5E                            pop esi
	0x3d23 C3                            ret 
	0x3d24 55                            push ebp
	0x3d25 8BEC                          mov ebp, esp
	0x3d27 56                            push esi
	0x3d28 8BF1                          mov esi, ecx
	 */
		$opcode_4 = {
			56
			8B F1
			8B 46 14
			83 F8 ??
			76 ??
		}

		$opcode_5 = {
			50
			FF 36
			E8 ?? ?? ?? ??
			59
			59
			83 66 ?? 00
		}
		$opcode_6 = {
			C7 46 14 ?? 00 00 00
			66 89 06
			5E
			C3
		}

	/*
	0x4304 55                            push ebp
	0x4305 8BEC                          mov ebp, esp
	0x4307 51                            push ecx
	0x4308 51                            push ecx
	0x4309 A1800D2F10                    mov eax, dword ptr [102f0d80h]
	0x430e 33C5                          xor eax, ebp
	0x4310 8945FC                        mov dword ptr [ebp - 4], eax
	0x4313 8B4D0C                        mov ecx, dword ptr [ebp + 0ch]
	0x4316 8B4508                        mov eax, dword ptr [ebp + 8]
	0x4319 8945F8                        mov dword ptr [ebp - 8], eax
	0x431c 81F900100000                  cmp ecx, 1000h
	0x4322 7215                          jb 4339h
	0x4324 8D450C                        lea eax, [ebp + 0ch]
	0x4327 50                            push eax
	0x4328 8D45F8                        lea eax, [ebp - 8]
	0x432b 50                            push eax
	0x432c E84BE8FFFF                    call 2b7ch
	0x4331 8B45F8                        mov eax, dword ptr [ebp - 8]
	0x4334 59                            pop ecx
	0x4335 59                            pop ecx
	 */
		$opcode_7 = {
			55
			8B EC
			51
			51
			A1 ?? ?? ?? ??
			33 C5
			89 45 FC
			8B 4D 0C
			8B 45 08
			89 45 F8
			81 F9 00 10 00 00
			72 ??
			8D 45 0C
			50
			8D 45 F8
			50
			E8 ?? ?? ?? ??
			8B 45 F8
			59
			59
		}

	condition:
		(uint16(0) == (0x5a4d) or uint32(0) == 0x46464952) 
		and filesize < 50000KB
		and all of them

}

rule Octowave_Loader_Supporting_File_03_2025
{
    meta:
        description = "Detects supporting file used by Octowave loader containing hardcoded values"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-19"
		  score = 75
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "C4CBAA7E4521FA0ED9CC634C5E2BACBF41F46842CA4526B7904D98843A7E9DB9"
        hash2 = "F5CFB2E634539D5DC7FFE202FFDC422EF7457100401BA1FBC21DD05558719865"
        hash3 = "56F1967F7177C166386D864807CDF03D5BBD3F118A285CE67EA226D02E5CF58C"
        hash4 = "11EE5AD8A81AE85E5B7DDF93ADF6EDD20DE8460C755BF0426DFCBC7F658D7E85"
        hash5 = "D218B65493E4D9D85CBC2F7B608F4F7E501708014BC04AF27D33D995AA54A703"
        hash6 = "0C112F9DFE27211B357C74F358D9C144EA10CC0D92D6420B8742B72A65562C5A"
        id = "2c81c8b8-4b4d-55c9-9285-556e8b5303bd"
    strings:
        $unique_key = {1D 1C 1F 1E 01 01 03 02 05 04 07 06 09 D4 0E 0A 0D 0C 0F 0E 31 30 31 32 35 34 36 36 39 38 DC 3F 3D 3C 3E} // 1012546698 unknown unique identifier and surrounding bytes
        $unique_string = "MLONqpsrutwvyx"
        $unique_string2 = "A@CBEDGFIHKJMLONqpsrutwvyx"
    condition:
        uint16(0) != 0x5a4d
        and filesize < 10000KB
        and all of them
}