rule Octowave_Loader_03_2025
{
	meta:
        description = "Detects opcodes found in Octowave Loader DLLs and WAV steganography files"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-19"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        x_reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "0504BFBACB6E10B81196F625F2FE37B33500E7BF65FD82D3510A2B178C6CD5BD"
        hash2 = "3A2DB0CB9EE01549A6B660D58115D112D36A744D65705394B54D7D95287C7A74"
        hash3 = "EB50D06057FE123D6E9F7A76D3D1A4BC5307E8F15D017BE8F6031E92136CF36A"
        hash4 = "24715920E749B014BA05F74C96627A27355C5860A14461C106AA48A7ABA371EA"
        shoutout = "https://yaratoolkit.securitybreak.io/"
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
			6A ??
			59
			AB
			AB
			AB
			AB
			8B 45 ??
			8B FA
			83 62 ?? ??
			8B F0
			83 62 ?? ??
			F3 A5
			83 60 ?? ??
		}

	condition:
		(uint16(0) == (0x5a4d) or uint32(0) ==  0x46464952) and any of them

}