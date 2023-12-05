
/* 
	SOURCE: https://github.com/chronicle/GCTI
	
	Generated with:
	cat ./GCTI/YARA/CobaltStrike/* >> ./signature-base/yara/gen_gcti_cobaltstrike.yar
*/

/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "243e3761-cbea-561c-97da-f6ba12ebc7ee"
	strings:
  // Decoder function for the embedded payload
	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash =  "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "4fff7f42-9f50-5945-8ec0-2438ac5c7000"
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+arg_8]
		8A [2]          mov     al, [edi+edx]
		30 ??           xor     [ebx], al
		8A ??           mov     al, [ebx]
		4?              inc     ebx
		88 [2]          mov     [esi+ecx], al
	*/

	$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }
	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash =  "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "8a010305-dce5-55f4-b2dd-a736721efe22"
	strings:
	/*
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+28h], 5Ch ; '\'
		C7 [3] 65 00 00 00  mov     dword ptr [esp+24h], 65h ; 'e'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+20h], 70h ; 'p'
		C7 [3] 69 00 00 00  mov     dword ptr [esp+1Ch], 69h ; 'i'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+18h], 70h ; 'p'
		F7 F1               div     ecx
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+14h], 5Ch ; '\'
		C7 [3] 2E 00 00 00  mov     dword ptr [esp+10h], 2Eh ; '.'
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+0Ch], 5Ch ; '\'
	*/

	$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
  $fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Disabled due to bad performance */
// rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
// {
// 	meta:
// 		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
// 		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
// 		author = "gssincla@google.com"
// 		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
// 		date = "2022-11-18"
		
// 	strings:
// 	/*
// 		8B [2]   mov     eax, [ebp+var_C]
// 		89 ??    mov     ecx, eax
// 		03 [2]   add     ecx, [ebp+lpBuffer]
// 		8B [2]   mov     eax, [ebp+var_C]
// 		03 [2]   add     eax, [ebp+lpBuffer]
// 		0F B6 18 movzx   ebx, byte ptr [eax]
// 		8B [2]   mov     eax, [ebp+var_C]
// 		89 ??    mov     edx, eax
// 		C1 [2]   sar     edx, 1Fh
// 		C1 [2]   shr     edx, 1Eh
// 		01 ??    add     eax, edx
// 		83 [2]   and     eax, 3
// 		29 ??    sub     eax, edx
// 		03 [2]   add     eax, [ebp+arg_8]
// 		0F B6 00 movzx   eax, byte ptr [eax]
// 		31 ??    xor     eax, ebx
// 		88 ??    mov     [ecx], al
// 	*/

// 	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
	
// 	condition:
// 		any of them
// }

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash =  "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "732169be-e334-5774-b0ac-54b217a8b681"
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+var_20]
		8A [2]          mov     al, [edi+edx]
		30 [2]          xor     [ebx+ecx], al
	*/

	$decoderFunc  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash =  "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "67902782-500e-5a89-8b2a-59ee21bcba3e"
	strings:
	/*
		8B [2]      mov     eax, [rbp+var_4]
		48 98       cdqe
		48 89 C1    mov     rcx, rax
		48 03 4D 10 add     rcx, [rbp+arg_0]
		8B 45 FC    mov     eax, [rbp+var_4]
		48 98       cdqe
		48 03 45 10 add     rax, [rbp+arg_0]
		44 0F B6 00 movzx   r8d, byte ptr [rax]
		8B 45 FC    mov     eax, [rbp+var_4]
		89 C2       mov     edx, eax
		C1 FA 1F    sar     edx, 1Fh
		C1 EA 1E    shr     edx, 1Eh
		01 D0       add     eax, edx
		83 E0 03    and     eax, 3
		29 D0       sub     eax, edx
		48 98       cdqe
		48 03 45 20 add     rax, [rbp+arg_10]
		0F B6 00    movzx   eax, byte ptr [rax]
		44 31 C0    xor     eax, r8d
		88 01       mov     [rcx], al
	*/

	$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }
		
	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash =  "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "c9e9b8e0-16fe-5abc-b1fe-0e3e586f6db6"
	strings:
	/*
		31 C0                xor     eax, eax
		EB 0F                jmp     short loc_6BAC16B5
		41 83 E1 03          and     r9d, 3
		47 8A 0C 08          mov     r9b, [r8+r9]
		44 30 0C 01          xor     [rcx+rax], r9b
		48 FF C0             inc     rax
		39 D0                cmp     eax, edx
		41 89 C1             mov     r9d, eax
		7C EA                jl      short loc_6BAC16A6
		4C 8D 05 53 29 00 00 lea     r8, aRundll32Exe; "rundll32.exe"
		E9 D1 FE FF FF       jmp     sub_6BAC1599
	*/

	$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash =  "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "1c7731d3-429b-57aa-9c17-8de7d0841b1e"
	strings:
	/*
		41 B8 5C 00 00 00       mov     r8d, 5Ch ; '\'
		C7 44 24 50 5C 00 00 00 mov     [rsp+68h+var_18], 5Ch ; '\'
		C7 44 24 48 65 00 00 00 mov     [rsp+68h+var_20], 65h ; 'e'
		C7 44 24 40 70 00 00 00 mov     [rsp+68h+var_28], 70h ; 'p'
		C7 44 24 38 69 00 00 00 mov     [rsp+68h+var_30], 69h ; 'i'
		C7 44 24 30 70 00 00 00 mov     [rsp+68h+var_38], 70h ; 'p'
		C7 44 24 28 5C 00 00 00 mov     dword ptr [rsp+68h+lpThreadId], 5Ch ; '\'
		C7 44 24 20 2E 00 00 00 mov     [rsp+68h+dwCreationFlags], 2Eh ; '.'
		89 54 24 58             mov     [rsp+68h+var_10], edx
		48 8D 15 22 38 00 00    lea     rdx, Format; Format
		E8 0D 17 00 00          call    sprintf
	*/

	$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}

  $fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Beacon_Dll_v1_44
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.44"
    hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "935ee27f-ce1b-5491-b4a3-cb78f199ab1b"
  strings:
    /*
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 5 cases
      53        push    ebx
      8B D9     mov     ebx, ecx; a2
      83 FA 04  cmp     edx, 4
      77 36     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10018F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10001AD4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }    
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.45"
    hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "04d4d0ee-f1ee-5888-8108-ca55243c770a"
  strings:
    /*
      51        push    ecx
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 9 cases
      53        push    ebx
      56        push    esi
      83 FA 08  cmp     edx, 8
      77 6B     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10019F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10002664
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.46"
    hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "79715042-1963-5e48-8b64-7d915da58d84"
  strings:
    /*
      8B F2             mov     esi, edx
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 8E 00 00 00 ja      def_1000107F; jumptable 1000107F default case, case 8
      FF 24 ??          jmp     ds:jpt_1000107F[ecx*4]; switch jump
    */   
    $version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001D040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_10002A04
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.47"
    hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "ac2249a9-210c-581f-8dd1-7619356dca7d"
  strings:
    /*
      83 F8 12  cmp     eax, 12h
      77 10     ja      short def_100010BB; jumptable 100010BB default case, case 8
      FF 24 ??  jmp     ds:jpt_100010BB[eax*4]; switch jump
    */
    $version_sig = { 83 F8 12 77 10 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001E040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.48"
    hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "dd15099f-ad19-58df-9ed4-ce66d7ee8540"
  strings:
    /*
      48        dec     eax; switch 24 cases
      57        push    edi
      8B F1     mov     esi, ecx
      8B DA     mov     ebx, edx
      83 F8 17  cmp     eax, 17h
      77 12     ja      short def_1000115D; jumptable 1000115D default case, case 8
      FF 24 ??  jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001F048[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_100047B4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.49"
    hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "871e28c9-b580-5a32-8529-2290ded1a1b6"
  strings:
    /*
      48                   dec     eax; switch 31 cases
      56                   push    esi
      83 F8 1E             cmp     eax, 1Eh
      0F 87 23 01 00 00    ja      def_1000115B; jumptable 1000115B default case, cases 8,30
      FF 24 85 80 12 00 10 jmp     ds:jpt_1000115B[eax*4]; switch jump
    */
    $version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
    
    /*
      B1 69            mov     cl, 69h ; 'i'
      90               nop
      30 88 [4]        xor     byte ptr word_10022038[eax], cl
      40               inc     eax
      3D A8 01 00 00   cmp     eax, 1A8h
      7C F2            jl      short loc_10005940
    */    
    $decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }
      
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
    hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "087c584a-5ceb-536a-8842-53fbd668df54"
  strings:
    /*
      83 F8 22          cmp     eax, 22h
      0F 87 96 01 00 00 ja      def_1000115D; jumptable 1000115D default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }

    /*
      B1 69            mov     cl, 69h ; 'i'
      EB 03            jmp     short loc_10006930
      8D 49 00         lea     ecx, [ecx+0]
      30 88 [4]        xor     byte ptr word_10023038[eax], cl
      40               inc     eax
      3D 30 05 00 00   cmp     eax, 530h
      72 F2            jb      short loc_10006930
    */
    $decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2
{
  // v2.1 and v2.2 use the exact same beacon binary (matching hashes)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
    hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "384fb247-aae7-52e1-a45d-6bda0f80a04e"
  strings:
    /*
      49                dec     ecx; switch 37 cases
      56                push    esi
      57                push    edi
      83 F9 24          cmp     ecx, 24h
      0F 87 8A 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
    hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "aed092f1-fbb1-5efe-be8d-fb7c5aba1cde"
  strings:
    /*
      49                dec     ecx; switch 39 cases
      56                push    esi
      57                push    edi
      83 F9 26          cmp     ecx, 26h
      0F 87 A9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
    hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "347a6b06-84a8-53ff-80a1-05fa1a48a412"
  strings:
    /*
      4A                dec     edx; switch 48 cases
      56                push    esi
      57                push    edi
      83 FA 2F          cmp     edx, 2Fh
      0F 87 F9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112E[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
    hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "a89f9239-099c-5b97-b1df-e8ce2b95ea52"
  strings:
    /*
      48                dec     eax; switch 59 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3A          cmp     eax, 3Ah
      0F 87 6E 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
    hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "132a1be8-f529-5141-ba03-fdf6df3d55d4"
  strings:
    /*
      48                dec     eax; switch 61 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3C          cmp     eax, 3Ch
      0F 87 89 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
    hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // v3.1 and v3.2 share the same C2 handler code. We are using a function that
  // is not included in v3.2 to mark the v3.1 version along with the decoder
  // which allows us to narrow in on only v3.1 samples
    id = "aa511dee-69ea-53bd-be90-d2d03d08c550"
  strings:
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "3ccbc0f2-241c-5c10-8930-4a3d264d3b57"
  strings:
    /*
      48                dec     eax; switch 62 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3D          cmp     eax, 3Dh
      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig
    // as a negating condition to diff between 3.1 and 3.2
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

  condition:
    $version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
    hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "7cce26c9-1403-535f-bd9d-19667c7e313c"
  strings:
    /*
      48                dec     eax; switch 66 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 41          cmp     eax, 41h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
    hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "58a34ab6-c061-59a2-b929-8519d3d844e7"
  strings:
    /*
      48                dec     eax; switch 67 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 42          cmp     eax, 42h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
  // Version 3.5-hf1 and 3.5.1 use the exact same beacon binary (same hash)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
    hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "1532596e-be0e-58c2-8d3b-5120c793d677"
  strings:
    /*
      48                dec     eax; switch 68 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 43          cmp     eax, 43h
      0F 87 07 03 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
    hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "7e7b5c22-82b3-5298-b794-b06d94a668d5"
  strings:
    /*
      48                dec     eax; switch 72 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 47          cmp     eax, 47h
      0F 87 2F 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
    hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "6352a31c-34b8-5886-8e34-ef9221c22e6e"
  strings:
    /*
      48                dec     eax; switch 74 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 49          cmp     eax, 49h
      0F 87 47 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */   
    $version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
    hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "6c65cbf8-2c60-5315-b3b2-48dfcee75733"
  strings:
    /*
      48                dec     eax; switch 76 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 4B          cmp     eax, 4Bh
      0F 87 5D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

    // XMRig uses a v3.8 sample to trick sandboxes into running their code. 
    // These samples are the same and useless. This string removes many
    // of them from our detection
    $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
    // To remove others, we look for known xmrig C2 domains in the config:
    $c2_1 = "ns7.softline.top" xor
    $c2_2 = "ns8.softline.top" xor
    $c2_3 = "ns9.softline.top" xor
    //$a = /[A-Za-z]{1020}.{4}$/
    
  condition:
    $version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)
}

/*

  missing specific signatures for 3.9 and 3.10 since we don't have samples

*/

rule CobaltStrike_Resources_Beacon_Dll_v3_11
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
    hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // Original version from April 9, 2018
    id = "00e42396-db81-5d43-90ee-5a97b379019e"
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 11 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
    hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
    rs2 ="4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  // Covers both 3.11 (bug fix form May 25, 2018) and v3.12
    id = "08ff2a2f-97bd-5839-b414-d67fbf2cdb0f"
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 0D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
    hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "98dd32e6-9bb5-57b2-a5e5-1c74a0d1e6d3"
  strings:
    /*
      4A                dec     edx; switch 91 cases
      56                push    esi
      57                push    edi
      83 FA 5A          cmp     edx, 5Ah
      0F 87 2D 03 00 00 ja      def_10008D01; jumptable 10008D01 default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??          jmp     ds:jpt_10008D01[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
    hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
    rs2 ="87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "00edfc72-c7b8-5100-8275-ae3548b96e49"
  strings:
    /*
      83 FA 5B  cmp     edx, 5Bh
      77 15     ja      short def_1000939E; jumptable 1000939E default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??  jmp     ds:jpt_1000939E[edx*4]; switch jump
    */
    $version_sig = { 83 FA 5B 77 15 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "50ff6e44-ebc0-5000-a816-b385a6675768"
  strings:
    /*
      51                   push    ecx
      4A                   dec     edx; switch 99 cases
      56                   push    esi
      57                   push    edi
      83 FA 62             cmp     edx, 62h
      0F 87 8F 03 00 00    ja      def_100077C3; jumptable 100077C3 default case, cases 2,6-8,20,21,25,26,30,34-36,63-66
      FF 24 95 56 7B 00 10 jmp     ds:jpt_100077C3[edx*4]; switch jump
    */

    $version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }

    /*
      80 B0 20 00 03 10 ??  xor     byte_10030020[eax], 2Eh
      40                    inc     eax
      3D 00 10 00 00        cmp     eax, 1000h
      7C F1                 jl      short loc_1000912B
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
    hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
    rs2 ="9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "793df916-bdf7-5743-b008-0113caf38bae"
  strings:
    /*
      48                dec     eax; switch 100 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 63          cmp     eax, 63h
      0F 87 3C 03 00 00 ja      def_10007F28; jumptable 10007F28 default case, cases 2,6-8,20,21,25,26,29,30,34-36,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007F28[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
    hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
    rs2 ="78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "976e087c-f371-5fc6-85f8-9c803a91f549"
  strings:
    /*
      48                dec     eax; switch 102 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 65          cmp     eax, 65h
      0F 87 47 03 00 00 ja      def_10007EAD; jumptable 10007EAD default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007EAD[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "4b6f90dd-69f3-5555-9195-6a0aed0fff58"
  strings:

    /*
      53                push    ebx
      56                push    esi
      48                dec     eax; switch 104 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 67          cmp     eax, 67h
      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
    */
    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }

    /*
      80 B0 [5]      xor     byte_10033020[eax], 2Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_1000ADA1
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

/*

 64-bit Beacons.
 
 These signatures are a bit different. The decoders are all identical in the 4.x
 series and the command processor doesn't use a switch/case idiom, but rather
 an expanded set of if/then/else branches. This invalidates our method for
 detecting the versions of the beacons by looking at the case count check
 used by the 32-bit versions. As such, we are locking in on "random",
 non-overlapping between version, sections of code in the command processor. 
 While a reasonable method is to look for blocks of Jcc which will have specific
 address offsets per version, this generally is insufficient due to the lack of 
 code changes. As such, the best method appears to be to look for specific
 function call offsets

 NOTE: There are only VERY subtle differences between the following versions:
  * 3.2 and 3.3
  * 3.4 and 3.5-hf1/3.5.1
  * 3.12, 3.13 and 3.14
  * 4.3 and 4.4-4.6 . 
  
 Be very careful if you modify the $version_sig field for either of those rules. 
*/


rule CobaltStrike_Resources_Beacon_x64_v3_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
    hash =  "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "61188243-0b90-5bff-bcc8-50f10ed941f6"
  strings:
    /*
      4C 8D 05 9F F8 FF FF lea     r8, sub_18000C4B0
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 05 1A 00 00       call    sub_18000E620
      EB 0A                jmp     short loc_18000CC27
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 41 21 00 00       call    sub_18000ED68
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
    
    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
    hash =  "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "fb96ecff-809e-5704-974e-a2d8ef022daa"
  strings:
    /*
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 89 66 00 00       call    sub_1800155E8
      E9 23 FB FF FF       jmp     loc_18000EA87
      41 B8 01 00 00 00    mov     r8d, 1
      E9 F3 FD FF FF       jmp     loc_18000ED62
      48 8D 0D 2A F8 FF FF lea     rcx, sub_18000E7A0
      E8 8D 2B 00 00       call    sub_180011B08
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
    hash =  "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "97ef152c-86c7-513c-a881-e7d594d38dcf"
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 56 6F 00 00    call    sub_180014458
      E9 17 FB FF FF    jmp     loc_18000D01E
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 41 4D 00 00    call    sub_180012258
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
    */
    $version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001600E
    */
    
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
    hash =  "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "0c0e87d3-e0e2-5ddc-9d89-5e56443da4b8"
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 38 70 00 00    call    sub_180014548
      E9 FD FA FF FF    jmp     loc_18000D012
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 3F 4D 00 00    call    sub_180012264
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
      5F                pop     rdi
    */

    $version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
    hash =  "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "9651a1ca-d8ea-5b0b-bcba-a850c2e07791"
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 27          cmp     ecx, 27h ; '''
      0F 87 47 03 00 00 ja      loc_18000D110
      0F 84 30 03 00 00 jz      loc_18000D0FF
      83 F9 14          cmp     ecx, 14h
      0F 87 A4 01 00 00 ja      loc_18000CF7C
      0F 84 7A 01 00 00 jz      loc_18000CF58
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 C8 00 00 00 ja      loc_18000CEAF
      0F 84 B3 00 00 00 jz      loc_18000CEA0
    */
    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
    hash =  "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "27fad98a-2882-5c52-af6e-c7dcf5559624"
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 28          cmp     ecx, 28h ; '('
      0F 87 7F 03 00 00 ja      loc_18000D148
      0F 84 67 03 00 00 jz      loc_18000D136
      83 F9 15          cmp     ecx, 15h
      0F 87 DB 01 00 00 ja      loc_18000CFB3
      0F 84 BF 01 00 00 jz      loc_18000CF9D
    */

    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016ECA
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
    hash =  "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "89809d81-9a8b-5cf3-a251-689bf52e98e0"
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 7A 52 00 00 call    sub_18001269C
      EB 0D          jmp     short loc_18000D431
      45 33 C0       xor     r8d, r8d
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi; Src
      E8 8F 55 00 00 call    sub_1800129C0
    */

    $version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001772E
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
    hash =  "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
    rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "bf0c7661-2583-5fca-beb5-abb2b50c860d"
  strings:
	
    /*
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 2D          cmp     ecx, 2Dh ; '-'
      0F 87 B2 03 00 00 ja      loc_18000D1EF
      0F 84 90 03 00 00 jz      loc_18000D1D3
      83 F9 17          cmp     ecx, 17h
      0F 87 F8 01 00 00 ja      loc_18000D044
      0F 84 DC 01 00 00 jz      loc_18000D02E
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 F9 00 00 00 ja      loc_18000CF54
      0F 84 DD 00 00 00 jz      loc_18000CF3E
      FF C9             dec     ecx
      0F 84 C0 00 00 00 jz      loc_18000CF29
      83 E9 02          sub     ecx, 2
      0F 84 A6 00 00 00 jz      loc_18000CF18
      FF C9             dec     ecx
    */

    $version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180017DCA
    */

    $decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
    hash =  "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "6eeae9f4-96e0-5a98-a8dc-779c916cd968"
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 F8 2E 00 00 call    sub_180010384
      EB 16          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 00 5C 00 00 call    f_OTH__Command_75
      EB 0A          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 64 4F 00 00 call    f_OTH__Command_74
    */
    $version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018205
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Resources_Beacon_x64_v3_13
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
    hash =  "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "202eb8ea-7afb-515b-9306-67514abf5e55"
  strings:
    /*
      48 8D 0D 01 5B FF FF lea     rcx, f_NET__ExfiltrateData
      48 83 C4 28          add     rsp, 28h
      E9 A8 54 FF FF       jmp     f_OTH__Command_85
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; lpSrc
      E8 22 55 FF FF       call    f_OTH__Command_84
    */

    $version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
      
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018C01
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
    hash =  "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
    rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "d69171e3-86f4-5187-8874-5eee2045f746"
  strings:

    /*
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Src
      48 83 C4 28    add     rsp, 28h
      E9 B1 1F 00 00 jmp     f_OTH__Command_69
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Source
      48 83 C4 28    add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800196BD
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "28a735c4-87d1-5e14-9379-46a6fd0cdd2a"
  strings:
    /*
      41 B8 01 00 00 00    mov     r8d, 1
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 D1 B3 FF FF       jmp     sub_180010C5C
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 AF F5 FF FF       jmp     f_UNK__Command_92__ChangeFlag
      45 33 C0             xor     r8d, r8d
      4C 8D 0D 8D 70 FF FF lea     r9, sub_18000C930
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      E8 9B B0 FF FF       call    f_OTH__Command_91__WrapInjection
    */

    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
    hash =  "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "dc320d17-98fc-5df3-ba05-4d134129317e"
  strings:
    /*
      83 F9 34          cmp     ecx, 34h ; '4'
      0F 87 8E 03 00 00 ja      loc_180016259
      0F 84 7A 03 00 00 jz      loc_18001624B
      83 F9 1C          cmp     ecx, 1Ch
      0F 87 E6 01 00 00 ja      loc_1800160C0
      0F 84 D7 01 00 00 jz      loc_1800160B7
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 E9 00 00 00 ja      loc_180015FD2
      0F 84 CE 00 00 00 jz      loc_180015FBD
      FF C9             dec     ecx
      0F 84 B8 00 00 00 jz      loc_180015FAF
      83 E9 02          sub     ecx, 2
      0F 84 9F 00 00 00 jz      loc_180015F9F
      FF C9             dec     ecx
    */

    $version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }


    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
    hash =  "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "572616c7-d1ec-5aa1-b142-4f2edf73737f"
  strings:
  
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 D3 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 84 6E FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
  
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800186E1
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
    hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "79b6bfd4-1e45-5bd9-ac5c-19eb176ce698"
  strings:
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 83 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 A4 6D FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }

    /*
      80 34 28 2E       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800184D9
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
    hash =  "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "45715da9-8f16-5304-b216-1ca36c508c77"
  strings:
    /*
      41 B8 01 00 00 00 mov     r8d, 1
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      48 83 C4 28       add     rsp, 28h
      E9 E8 AB FF FF    jmp     sub_1800115A4
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      E8 1A EB FF FF    call    f_UNK__Command_92__ChangeFlag
      48 83 C4 28       add     rsp, 28h
    */
    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018E1F
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		hash =  "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "a01e7bc3-40e9-5f87-8fd6-926972be273b"
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the inclusion of additional calls
  // found in bind64 to differentate between this and reverse64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA C2 DB 37 67 mov     r10d, bind
		FF D5             call    rbp
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA B7 E9 38 FF mov     r10d, listen
		FF D5             call    rbp
		4D 31 C0          xor     r8, r8
		48 31 D2          xor     rdx, rdx
		48 89 F9          mov     rcx, rdi
		41 BA 74 EC 3B E1 mov     r10d, accept
		FF D5             call    rbp
		48 89 F9          mov     rcx, rdi
		48 89 C7          mov     rdi, rax
		41 BA 75 6E 4D 61 mov     r10d, closesocket
	*/

	$calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}
		
	condition:
		$apiLocator and $calls
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash =  "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "32f129c1-9845-5843-9e16-7d9af217b8e2"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for bind.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}

  // bind.bin, unlike reverse.bin, listens for incoming connections. Using the API hashes for listen and accept is a solid
  // approach to finding bind.bin specific samples
	/*
		5?             push    ebx
		5?             push    edi
		68 B7 E9 38 FF push    listen
		FF ??          call    ebp
		5?             push    ebx
		5?             push    ebx
		5?             push    edi
		68 74 EC 3B E1 push    accept
	*/
	$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}
	
	condition:
		$apiLocator and $ws2_32 and $listenaccept
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule  CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash =  "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "55086544-6684-526b-914f-505a562be458"
	strings:
	/*
		FF [1-5]        call    ds:recv               // earlier versions (v1.x to 2.x) this is CALL EBP
		83 ?? FF        cmp     eax, 0FFFFFFFFh
		74 ??           jz      short loc_100020D5
		85 C0           test    eax, eax
		(74  | 76) ??   jz      short loc_100020D5    // earlier versions (v1.x to 2.x) used jbe (76) here
		03 ??           add     esi, eax
		83 ?? 02        cmp     esi, 2
		72 ??           jb      short loc_100020D1
		80 ?? 3E FF 0A  cmp     byte ptr [esi+edi-1], 0Ah
		75 ??           jnz     short loc_100020D1
		80 ?? 3E FE 0D  cmp     byte ptr [esi+edi-2], 0Dh
	*/

	$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		
  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash =  "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "a5dfae85-ff9c-5ca5-9ac0-041c6108a6ed"
	strings:
	/*
		FF 15 [4]         call    cs:recv
		83 ?? FF          cmp     eax, 0FFFFFFFFh
		74 ??             jz      short loc_1800018FB
		85 ??             test    eax, eax
		74 ??             jz      short loc_1800018FB
		03 ??             add     ebx, eax
		83 ?? 02          cmp     ebx, 2
		72 ??             jb      short loc_1800018F7
		8D ?? FF          lea     eax, [rbx-1]
		80 [2] 0A         cmp     byte ptr [rax+rdi], 0Ah
		75 ??             jnz     short loc_1800018F7
		8D ?? FE          lea     eax, [rbx-2]
		80 [2] 0D         cmp     byte ptr [rax+rdi], 0Dh
	*/

	$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}

  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"
		
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash =  "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "614046b5-cf81-56a5-8824-b3a7e14a8ed5"
	strings:
	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		8B ??     mov     ecx, [eax]
		5?        push    edx
		5?        push    eax
		FF ?? 48  call    dword ptr [ecx+48h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001177
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		FF ?? 08  push    [ebp+copyName]
		8B ??     mov     ecx, [eax]
		FF [5]    push    dstFile
		FF [5]    push    srcFile
		5?        push    eax
		FF ?? 40  call    dword ptr [ecx+40h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001026  // this line can also be 0F 85 <32-bit offset>
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		
				
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash =  "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "eef83901-63d9-55a3-b115-03f420416177"
	strings:
	/*
		48 8B 0D 07 A4 01 00 mov     rcx, cs:fileop
		45 33 C0             xor     r8d, r8d
		48 8B 01             mov     rax, [rcx]
		FF 90 90 00 00 00    call    qword ptr [rax+90h]
		85 C0                test    eax, eax
		75 D9                jnz     short loc_180001022
		48 8B 0D F0 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
		85 C0                test    eax, eax
	*/

	$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}	
	
	
	/*
		48 8B 0D 32 A3 01 00 mov     rcx, cs:fileop
		4C 8B 05 3B A3 01 00 mov     r8, cs:dstFile
		48 8B 15 2C A3 01 00 mov     rdx, cs:srcFile
		48 8B 01             mov     rax, [rcx]
		4C 8B CD             mov     r9, rbp
		48 89 5C 24 20       mov     [rsp+38h+var_18], rbx
		FF 90 80 00 00 00    call    qword ptr [rax+80h]
		85 C0                test    eax, eax
		0F 85 7B FF FF FF    jnz     loc_1800010B0
		48 8B 0D 04 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
	*/

	$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash =  "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "b9f25fa5-bd1d-5ba0-9b1d-bb97e1dbf76b"
	strings:
	/*
		5?                 push    eax; ReturnLength
		5?                 push    edi; TokenInformationLength
		5?                 push    edi; TokenInformation
		8B ??              mov     ebx, ecx
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		75 ??              jnz     short loc_10001100
		FF 15 [4]          call    ds:GetLastError
		83 ?? 7A           cmp     eax, 7Ah ; 'z'
		75 ??              jnz     short loc_10001100
		FF [2]             push    [ebp+ReturnLength]; uBytes
		5?                 push    edi; uFlags
		FF 15 [4]          call    ds:LocalAlloc
		8B ??              mov     esi, eax
		8D [2]             lea     eax, [ebp+ReturnLength]
		5?                 push    eax; ReturnLength
		FF [2]             push    [ebp+ReturnLength]; TokenInformationLength
		5?                 push    esi; TokenInformation
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		74 ??              jz      short loc_10001103
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthorityCount
		8A ??              mov     al, [eax]
		FE C8              dec     al
		0F B6 C0           movzx   eax, al
		5?                 push    eax; nSubAuthority
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthority
		B? 01 00 00 00     mov     ecx, 1
		5?                 push    esi; hMem
		81 ?? 00 30 00 00  cmp     dword ptr [eax], 3000h
	*/

	$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}

	/*
		6A 3C               push    3Ch ; '<'; Size
		8D ?? C4            lea     eax, [ebp+pExecInfo]
		8B ??               mov     edi, edx
		6A 00               push    0; Val
		5?                  push    eax; void *
		8B ??               mov     esi, ecx
		E8 [4]              call    _memset
		83 C4 0C            add     esp, 0Ch
		C7 [2] 3C 00 00 00  mov     [ebp+pExecInfo.cbSize], 3Ch ; '<'
		8D [2]              lea     eax, [ebp+pExecInfo]
		C7 [2] 40 00 00 00  mov     [ebp+pExecInfo.fMask], 40h ; '@'
		C7 [6]              mov     [ebp+pExecInfo.lpFile], offset aTaskmgrExe; "taskmgr.exe"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpParameters], 0
		5?                  push    eax; pExecInfo
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpDirectory], 0
		C7 [6]              mov     [ebp+pExecInfo.lpVerb], offset aRunas; "runas"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.nShow], 0
		FF 15 [4]           call    ds:ShellExecuteExW
		FF 75 FC            push    [ebp+pExecInfo.hProcess]; Process
	*/

	$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}
		
	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash =  "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "c89befcd-a622-5947-9ce3-a6031901a45a"
	strings:
	/*
		83 F8 7A          cmp     eax, 7Ah ; 'z'
		75 59             jnz     short loc_1800014BC
		8B 54 24 48       mov     edx, dword ptr [rsp+38h+uBytes]; uBytes
		33 C9             xor     ecx, ecx; uFlags
		FF 15 49 9C 00 00 call    cs:LocalAlloc
		44 8B 4C 24 48    mov     r9d, dword ptr [rsp+38h+uBytes]; TokenInformationLength
		8D 53 19          lea     edx, [rbx+19h]; TokenInformationClass
		48 8B F8          mov     rdi, rax
		48 8D 44 24 48    lea     rax, [rsp+38h+uBytes]
		48 8B CE          mov     rcx, rsi; TokenHandle
		4C 8B C7          mov     r8, rdi; TokenInformation
		48 89 44 24 20    mov     [rsp+38h+ReturnLength], rax; ReturnLength
		FF 15 B0 9B 00 00 call    cs:GetTokenInformation
		85 C0             test    eax, eax
		74 2D             jz      short loc_1800014C1
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 AB 9B 00 00 call    cs:GetSidSubAuthorityCount
		8D 73 01          lea     esi, [rbx+1]
		8A 08             mov     cl, [rax]
		40 2A CE          sub     cl, sil
		0F B6 D1          movzx   edx, cl; nSubAuthority
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 9F 9B 00 00 call    cs:GetSidSubAuthority
		81 38 00 30 00 00 cmp     dword ptr [rax], 3000h
	*/

	$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}

	/*
		44 8D 42 70             lea     r8d, [rdx+70h]; Size
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; void *
		E8 2E 07 00 00          call    memset
		83 64 24 50 00          and     [rsp+98h+pExecInfo.nShow], 0
		48 8D 05 E2 9B 00 00    lea     rax, aTaskmgrExe; "taskmgr.exe"
		0F 57 C0                xorps   xmm0, xmm0
		66 0F 7F 44 24 40       movdqa  xmmword ptr [rsp+98h+pExecInfo.lpParameters], xmm0
		48 89 44 24 38          mov     [rsp+98h+pExecInfo.lpFile], rax
		48 8D 05 E5 9B 00 00    lea     rax, aRunas; "runas"
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; pExecInfo
		C7 44 24 20 70 00 00 00 mov     [rsp+98h+pExecInfo.cbSize], 70h ; 'p'
		C7 44 24 24 40 00 00 00 mov     [rsp+98h+pExecInfo.fMask], 40h ; '@'
		48 89 44 24 30          mov     [rsp+98h+pExecInfo.lpVerb], rax
		FF 15 05 9B 00 00       call    cs:ShellExecuteExW
	*/

	$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}


	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash =  "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

		id = "c0b81deb-ed20-5f7e-8e15-e6a9e9362594"
  strings:		
    // the command.ps1 and compress.ps1 are the same file. Between v3.7 and v3.8 the file was renamed from command to compress.
    $ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
    $ps2 ="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase
  
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash =  "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "a65b855c-5703-5b9f-bb57-da8ebf898f9b"
	strings:
	/*
		5?                  push    esi
		68 [4]              push    offset ProcName; "IsWow64Process"
		68 [4]              push    offset ModuleName; "kernel32"
		C7 [3-5] 00 00 00 00  mov     [ebp+var_9C], 0                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		FF 15 [4]           call    ds:GetModuleHandleA
		50                  push    eax; hModule
		FF 15 [4]           call    ds:GetProcAddress
		8B ??               mov     esi, eax
		85 ??               test    esi, esi
		74 ??               jz      short loc_1000298B
		8D [3-5]            lea     eax, [ebp+var_9C]                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		5?                  push    eax
		FF 15 [4]           call    ds:GetCurrentProcess
		50                  push    eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}

	/*
		6A 00          push    0; AccessMode
		5?             push    esi; FileName
		E8 [4]         call    __access
		83 C4 08       add     esp, 8
		83 F8 FF       cmp     eax, 0FFFFFFFFh
		74 ??          jz      short loc_100028A7
		5?             push    esi
		68 [4]         push    offset aWarningSExists; "Warning: %s exists\n"   // this may not exist in v2.x samples
		E8 [4]         call    nullsub_1
		83 C4 08       add     esp, 8             // if the push doesnt exist, then this is 04, not 08
		// v2.x has a PUSH ESI here... so we need to skip that
		6A 00          push    0; hTemplateFile
		68 80 01 00 00 push    180h; dwFlagsAndAttributes
		6A 02          push    2; dwCreationDisposition
		6A 00          push    0; lpSecurityAttributes
		6A 05          push    5; dwShareMode
		68 00 00 00 40 push    40000000h; dwDesiredAccess
		5?             push    esi; lpFileName
		FF 15 [4]      call    ds:CreateFileA
		8B ??          mov     edi, eax
		83 ?? FF       cmp     edi, 0FFFFFFFFh
		75 ??          jnz     short loc_100028E2
		FF 15 [4]      call    ds:GetLastError
		5?             push    eax
	*/

	$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
	
	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash =  "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "48485ae2-1d99-5fa8-b8e8-0047e92ef447"
	strings:
	/*
		C7 04 24 [4]    mov     dword ptr [esp], offset aKernel32; "kernel32"
		E8 [4]          call    GetModuleHandleA
		83 EC 04        sub     esp, 4
		C7 44 24 04 [4] mov     dword ptr [esp+4], offset aIswow64process; "IsWow64Process"
		89 04 24        mov     [esp], eax; hModule
		E8 59 14 00 00  call    GetProcAddress
		83 EC 08        sub     esp, 8
		89 45 ??        mov     [ebp+var_C], eax
		83 7D ?? 00     cmp     [ebp+var_C], 0
		74 ??           jz      short loc_4019BA
		E8 [4]          call    GetCurrentProcess
		8D [2]          lea     edx, [ebp+fIs64bit]
		89 [3]          mov     [esp+4], edx
		89 04 24        mov     [esp], eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}

	/*
		C7 44 24 04 00 00 00 00 mov     dword ptr [esp+4], 0; AccessMode
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24                mov     [esp], eax; FileName
		E8 [4]                  call    _access
		83 F8 FF                cmp     eax, 0FFFFFFFFh
		74 ??                   jz      short loc_40176D
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24 04             mov     [esp+4], eax
		C7 04 24 [4]            mov     dword ptr [esp], offset aWarningSExists; "Warning: %s exists\n"
		E8 [4]                  call    log
		E9 [4]                  jmp     locret_401871
		C7 44 24 18 00 00 00 00 mov     dword ptr [esp+18h], 0; hTemplateFile
		C7 44 24 14 80 01 00 00 mov     dword ptr [esp+14h], 180h; dwFlagsAndAttributes
		C7 44 24 10 02 00 00 00 mov     dword ptr [esp+10h], 2; dwCreationDisposition
		C7 44 24 0C 00 00 00 00 mov     dword ptr [esp+0Ch], 0; lpSecurityAttributes
		C7 44 24 08 05 00 00 00 mov     dword ptr [esp+8], 5; dwShareMode
		C7 44 24 04 00 00 00 40 mov     dword ptr [esp+4], 40000000h; dwDesiredAccess
		8B [2]                  mov     eax, [ebp+FileName]
		89 04 24                mov     [esp], eax; lpFileName
		E8 [4]                  call    CreateFileA
		83 EC 1C                sub     esp, 1Ch
		89 45 ??                mov     [ebp+hFile], eax
	*/

	$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}

	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase
			
	condition:
		all of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		hash =  "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "e1b0e368-9bcf-5d9b-b2b3-8414742f213e"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for dnsstager.bin specific bytes helps delineate sample types
	  $dnsapi = { 68 64 6E 73 61 }	
	
	condition:
		$apiLocator and $dnsapi
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash =  "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "170f62a2-ba4f-5be8-9ec5-402eb7bbde4e"
	strings:
	/*
		6A 00               push    0; lParam
		6A 28               push    28h ; '('; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		C7 [5] 01 00 00 00  mov     dword_10017E70, 1
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 27               push    27h ; '''; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 00               push    0; wParam
		68 01 02 00 00      push    201h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
	*/

	$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

		
	condition:
		$wnd_proc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash =  "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "91d5c343-1084-5cfc-9dfa-46f530eb9625"
	strings:
	/*
		81 FA 21 01 00 00             cmp     edx, 121h
		75 4A                         jnz     short loc_1800017A9
		83 3D 5A 7E 01 00 00          cmp     cs:dword_1800195C0, 0
		75 41                         jnz     short loc_1800017A9
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		C7 05 48 7E 01 00 01 00 00 00 mov     cs:dword_1800195C0, 1
		45 8D 41 28                   lea     r8d, [r9+28h]; wParam
		FF 15 36 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		45 8D 41 27                   lea     r8d, [r9+27h]; wParam
		48 8B CB                      mov     rcx, rbx; hWnd
		FF 15 23 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		45 33 C0                      xor     r8d, r8d; wParam
		BA 01 02 00 00                mov     edx, 201h; Msg
		48 8B CB                      mov     rcx, rbx; hWnd
	*/

	$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		hash =  "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "c16e73fc-484a-5f7e-8127-d85a0254d842"
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		BA 1F 00 00 00    mov     edx, 1Fh
		6A 00             push    0
		68 80 33 00 00    push    3380h
		49 89 E0          mov     r8, rsp
		41 B9 04 00 00 00 mov     r9d, 4
		41 BA 75 46 9E 86 mov     r10d, InternetSetOptionA
	*/

	$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}	
	
	condition:
		$apiLocator and $InternetSetOptionA
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash =  "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "f45aa40a-3936-50f9-a60e-de7181862d19"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the inclusion of the InternetSetOptionA call. We will trigger off that API
	/*
		6A 04          push    4
		5?             push    eax
		6A 1F          push    1Fh
		5?             push    esi
		68 75 46 9E 86 push    InternetSetOptionA
		FF ??          call    ebp
	*/

	$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}
	
	condition:
		$apiLocator and $InternetSetOptionA
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash =  "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "5530dce8-e5a1-5133-9b05-464e3397084a"
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for httpstager64 and httpsstager64 really the inclusion or exclusion of InternetSetOptionA. However,
  // there is a subtle difference in the jmp after the InternetOpenA call (short jmp for x86 and long jmp for x64)
	/*
		41 BA 3A 56 79 A7 mov     r10d, InternetOpenA
		FF D5             call    rbp
		EB 61             jmp     short j_get_c2_ip
	*/

	$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	
	condition:
		$apiLocator and $postInternetOpenJmp
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash =  "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "86109485-c26c-5c51-8d04-dd1add9a8c57"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API
  // and the httpstager controls the download loop slightly different than the httpsstager
	/*
		B? 00 2F 00 00  mov     edi, 2F00h
		39 ??           cmp     edi, eax
		74 ??           jz      short loc_100000E9
		31 ??           xor     edi, edi
		E9 [4]          jmp     loc_100002CA      // opcode could also be EB for a short jump (v2.5-v3.10)
	*/

	$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash =  "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "966e6e4c-85e2-5c94-8245-25367802b7d2"
	strings:
	/*
		48 31 C0       xor     rax, rax
		AC             lodsb
		41 C1 C9 0D    ror     r9d, 0Dh
		41 01 C1       add     r9d, eax
		38 E0          cmp     al, ah
		75 F1          jnz     short loc_100000000000007D
		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]
		45 39 D1       cmp     r9d, r10d
		75 D8          jnz     short loc_100000000000006E
		58             pop     rax
		44 8B 40 24    mov     r8d, [rax+24h]
		49 01 D0       add     r8, rdx
		66 41 8B 0C 48 mov     cx, [r8+rcx*2]
		44 8B 40 1C    mov     r8d, [rax+1Ch]
		49 01 D0       add     r8, rdx
		41 8B 04 88    mov     eax, [r8+rcx*4]
		48 01 D0       add     rax, rdx
	*/

	$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}


  // the signature for reverse64 and bind really differ slightly, here we are using the lack of additional calls
  // found in reverse64 to differentate between this and bind64
  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,
  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be
  // unchanged. This means we can use these values as anchors in our signature.
	/*
		41 BA EA 0F DF E0 mov     r10d, WSASocketA
		FF D5             call    rbp
		48 89 C7          mov     rdi, rax
		6A 10             push    10h
		41 58             pop     r8
		4C 89 E2          mov     rdx, r12
		48 89 F9          mov     rcx, rdi
		41 BA 99 A5 74 61 mov     r10d, connect
		FF D5             call    rbp
	*/

	$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}
	condition:
		$apiLocator and $calls
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash =  "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "182dbcd0-1180-5516-abe3-cf2eebbd0e39"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for reverse.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}


  // reverse.bin makes outbound connection (using connect) while bind.bin listens for incoming connections (using listen)
  // so the presence of the connect API hash is a solid method for distinguishing between the two.
	/*
		6A 10          push    10h
		[0]5?          push    esi
		5?             push    edi
		68 99 A5 74 61 push    connect
	*/
	$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}
	
	condition:
		$apiLocator and $ws2_32 and $connect
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash =  "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "074b7d83-e3d8-541c-804b-2417c21f54d5"
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for smbstager.bin specific bytes helps delineate sample types
	  $smb = { 68 C6 96 87 52 }	
	  
	  // This code block helps differentiate between smbstager.bin and metasploit's engine which has reasonable level of overlap
	  	/*
		6A 40          push    40h ; '@'
		68 00 10 00 00 push    1000h
		68 FF FF 07 00 push    7FFFFh
		6A 00          push    0
		68 58 A4 53 E5 push    VirtualAlloc
	*/

	$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}
	
	condition:
		$apiLocator and $smb and $smbstart
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash =  "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

		id = "16aef9a9-b217-5462-93dc-f6273c99ddd0"
  strings:   
    $arch = "platform.architecture()"
    $nope = "WindowsPE"
    $alloc = "ctypes.windll.kernel32.VirtualAlloc"
    $movemem = "ctypes.windll.kernel32.RtlMoveMemory"
    $thread = "ctypes.windll.kernel32.CreateThread"
    $wait = "ctypes.windll.kernel32.WaitForSingleObject"

  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

		id = "9d2b1dfa-5f76-503f-9198-6ed0d039e0cb"
	strings:
    $scriptletstart = "<scriptlet>" nocase
    $registration = "<registration progid=" nocase
    $classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
    $scriptend = "</script>" nocase
	  $antiregistration = "</registration>" nocase
    $scriptletend = "</scriptlet>"

  condition:
    all of them and @scriptletstart[1] < @registration[1] and @registration[1] < @classid[1] and @classid[1] < @scriptlang[1] and @scriptlang[1] < @cdata[1]
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash =  "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "62f35d02-1e4e-5651-b575-888ce06b8bdd"
	strings:
	  $ea = "Excel.Application" nocase
    $vis = "Visible = False" nocase
    $wsc = "Wscript.Shell" nocase
    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
    $regwrite = ".RegWrite" nocase
    $dw = "REG_DWORD"
    $code = ".CodeModule.AddFromString"
	 /* Hex encoded Auto_*/ /*Open */
    $ao = { 41 75 74 6f 5f 4f 70 65 6e }
    $da = ".DisplayAlerts"

  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "c9fa6a39-0098-5dde-9762-94bc6b2df299"
	strings:
	
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
    $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
    $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
    $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
    $paramsGIM = ".GenerateInMemory = $True" nocase
    $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
    //$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    //$64bitSpecific = "[IntPtr]::size -eq 8"
    
    
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "5a808113-aacb-56ca-b3ec-166c73c54b85"
	strings:
    $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
    $imm = "InMemoryModule" nocase
    $mdt = "MyDelegateType" nocase
    $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
    $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
    $64bitSpecific = "[IntPtr]::size -eq 8"
    $mandatory = "Mandatory = $True"
    
  condition:
    all of them
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

		id = "11c7758e-93b2-5fe3-873d-b98de579d2b4"
	strings:
    $createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
    $allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
    $writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
    $runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
    $vars = "Dim rwxpage As Long" nocase
    $res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
    $rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

  condition:
    all of them and @vars[1] < @res[1] and @allocstuff[1] < @rwxpage[1]
}/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash =  "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "1754746c-3a42-5f7d-808a-ba2e1c0a270e"
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */
    $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
    $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

  condition:
    any of them
}


/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash =  "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "5bb465ee-3bbd-5bfe-8b63-1f243de217bc"
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor64.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */

    $stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
    $stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
    $stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}
  
  condition:
    any of them
}
 /*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
   
    id = "0ee3fa6f-367c-596f-a3bc-3bcfa61b97aa"
  strings:
    /*
      C6 45 F0 48 mov     [ebp+var_10], 48h ; 'H'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 61 mov     [ebp+var_E], 61h ; 'a'
      C6 45 F3 70 mov     [ebp+var_D], 70h ; 'p'
      C6 45 F4 41 mov     [ebp+var_C], 41h ; 'A'
      C6 45 F5 6C mov     [ebp+var_B], 6Ch ; 'l'
      C6 45 F6 6C mov     [ebp+var_A], 6Ch ; 'l'
      C6 45 F7 6F mov     [ebp+var_9], 6Fh ; 'o'
      C6 45 F8 63 mov     [ebp+var_8], 63h ; 'c'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9B 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "3f7c0553-989e-53e7-87a9-3fa1c47f4b62"
  strings:
    /*
      C6 45 EC 4D mov     [ebp+var_14], 4Dh ; 'M'
      C6 45 ED 61 mov     [ebp+var_13], 61h ; 'a'
      C6 45 EE 70 mov     [ebp+var_12], 70h ; 'p'
      C6 45 EF 56 mov     [ebp+var_11], 56h ; 'V'
      C6 45 F0 69 mov     [ebp+var_10], 69h ; 'i'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 77 mov     [ebp+var_E], 77h ; 'w'
      C6 45 F3 4F mov     [ebp+var_D], 4Fh ; 'O'
      C6 45 F4 66 mov     [ebp+var_C], 66h ; 'f'
      C6 45 F5 46 mov     [ebp+var_B], 46h ; 'F'
      C6 45 F6 69 mov     [ebp+var_A], 69h ; 'i'
      C6 45 F7 6C mov     [ebp+var_9], 6Ch ; 'l'
      C6 45 F8 65 mov     [ebp+var_8], 65h ; 'e'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9C 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "5f89c4be-f4c5-54d3-b923-d125de53902f"
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "32a47966-f3bb-52c3-a977-82a1b09ddf2c"
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    $core_sig and not $deobfuscator
}


// 64-bit BeaconLoaders

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "9b16ff13-2d8e-51dc-9f99-6c45eff76feb"
  strings:
    /*
      C6 44 24 38 48 mov     [rsp+78h+var_40], 48h ; 'H'
      C6 44 24 39 65 mov     [rsp+78h+var_3F], 65h ; 'e'
      C6 44 24 3A 61 mov     [rsp+78h+var_3E], 61h ; 'a'
      C6 44 24 3B 70 mov     [rsp+78h+var_3D], 70h ; 'p'
      C6 44 24 3C 41 mov     [rsp+78h+var_3C], 41h ; 'A'
      C6 44 24 3D 6C mov     [rsp+78h+var_3B], 6Ch ; 'l'
      C6 44 24 3E 6C mov     [rsp+78h+var_3A], 6Ch ; 'l'
      C6 44 24 3F 6F mov     [rsp+78h+var_39], 6Fh ; 'o'
      C6 44 24 40 63 mov     [rsp+78h+var_38], 63h ; 'c'
      C6 44 24 41 00 mov     [rsp+78h+var_37], 0
    */

    $core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D1 56 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "38e063db-3d76-5a94-812a-945fcf46a232"
  strings:
    /*
      C6 44 24 58 4D mov     [rsp+98h+var_40], 4Dh ; 'M'
      C6 44 24 59 61 mov     [rsp+98h+var_3F], 61h ; 'a'
      C6 44 24 5A 70 mov     [rsp+98h+var_3E], 70h ; 'p'
      C6 44 24 5B 56 mov     [rsp+98h+var_3D], 56h ; 'V'
      C6 44 24 5C 69 mov     [rsp+98h+var_3C], 69h ; 'i'
      C6 44 24 5D 65 mov     [rsp+98h+var_3B], 65h ; 'e'
      C6 44 24 5E 77 mov     [rsp+98h+var_3A], 77h ; 'w'
      C6 44 24 5F 4F mov     [rsp+98h+var_39], 4Fh ; 'O'
      C6 44 24 60 66 mov     [rsp+98h+var_38], 66h ; 'f'
      C6 44 24 61 46 mov     [rsp+98h+var_37], 46h ; 'F'
      C6 44 24 62 69 mov     [rsp+98h+var_36], 69h ; 'i'
      C6 44 24 63 6C mov     [rsp+98h+var_35], 6Ch ; 'l'
      C6 44 24 64 65 mov     [rsp+98h+var_34], 65h ; 'e'
    */

    $core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D2 57 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "8ca04f82-a8a8-5162-8b0c-8a7bce678a85"
  strings:
    /*
      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'
      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'
      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'
      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'
      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'
      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'
      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'
      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'
      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'
      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'
      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'
      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'
      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0
    */

    $core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }


    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
    id = "07f751e4-f001-5b95-b229-31fbaa867cea"
  strings:
    /*
      33 C0                      xor     eax, eax
      83 F8 01                   cmp     eax, 1
      74 63                      jz      short loc_378
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      0F B7 00                   movzx   eax, word ptr [rax]
      3D 4D 5A 00 00             cmp     eax, 5A4Dh
      75 45                      jnz     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 63 40 3C                movsxd  rax, dword ptr [rax+3Ch]
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 83 7C 24 28 40          cmp     [rsp+38h+var_10], 40h ; '@'
      72 2F                      jb      short loc_369
      48 81 7C 24 28 00 04 00 00 cmp     [rsp+38h+var_10], 400h
      73 24                      jnb     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 8B 4C 24 28             mov     rcx, [rsp+38h+var_10]
      48 03 C8                   add     rcx, rax
      48 8B C1                   mov     rax, rcx
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 8B 44 24 28             mov     rax, [rsp+38h+var_10]
      81 38 50 45 00 00          cmp     dword ptr [rax], 4550h
      75 02                      jnz     short loc_369
    */

    $core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }

    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    $core_sig and not $deobfuscator
}
