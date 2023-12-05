import "pe"

rule MAL_Shellcode_Loader_Apr23 {
   meta:
      author = "X__Junior (Nextron Systems)"
      reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
      description = "Detects Shellcode loader as seen being used by Gopuram backdoor"
      date = "2023-04-03"
      hash1 = "6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad"
      hash2 = "b56279136d816a11cf4db9fc1b249da04b3fa3aef4ba709b20cdfbe572394812"
      score = 80
      id = "363b67d6-9cac-513d-a545-1f256667bab8"
   strings:
      $op1 = { 41 C1 CB 0D 0F BE 03 48 FF C3 44 03 D8 80 7B ?? 00 75 ?? 41 8D 04 13 3B C6 74 } // API hahsing
      $op2 = { B9 49 F7 02 78 4C 8B E8 E8 ?? ?? ?? ?? B9 58 A4 53 E5 48 89 44 24 ?? E8 ?? ?? ?? ?? B9 10 E1 8A C3 48 8B F0 E8 ?? ?? ?? ?? B9 AF B1 5C 94 48 89 44 24 ?? E8 } // pushing API hashes
   condition:
      all of them
}
 
rule APT_MAL_Gopuram_Backdoor_Apr23 {
   meta:
      author = "X__Junior (Nextron Systems)"
      reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
      description = "Detects Gopuram backdoor"
      date = "2023-02-24"
      hash1 = "beb775af5196f30e0ee021790a4978ca7a7ac2a7cf970a5a620ffeb89cc60b2c"
      hash2 = "97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"
      score = 80
      id = "3ae5ddcb-5601-5dca-85dd-0a4772577fae"
   strings:
      $x1 = "%s\\config\\TxR\\%s.TxR.0.regtrans-m"  ascii
      $xop = { D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE } // operations on filename

      $opa1 = { 48 89 44 24 ?? 45 33 C9 45 33 C0 33 D2 89 5C 24 ?? 48 89 74 24 ?? 48 89 5C 24 ?? 89 7C 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 4C 24 ?? 44 8D 43 } // decrypt and Virtualprotect
      $opa2 = { 48 89 B4 24 ?? ?? ?? ?? 44 8D 43 ?? 33 D2 48 89 BC 24 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 45 33 C0 33 D2 8B F8 E8 ?? ?? ?? ?? 8D 4F ?? E8 ?? ?? ?? ?? 4C 8B 4C 24 ?? 44 8D 43 ?? 48 8B C8 8B D7 48 8B F0 44 8B F7 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8  } // read file content
   condition:
      ( uint16(0) == 0x5A4D and filesize < 2MB
        and pe.characteristics & pe.DLL and 1 of ($x*)
      )
      or all of ($opa*)
}

rule APT_NK_MAL_DLL_Apr23_1 {
   meta:
      description = "Detects DLLs loaded by shellcode loader (6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad) (relation to Lazarus group)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
      date = "2023-04-03"
      score = 75
      hash1 = "69dd140f45c3fa3aaa64c69f860cd3c74379dec37c46319d7805a29b637d4dbf"
      hash3 = "bb1066c1ca53139dc5a2c1743339f4e6360d6fe4f2f3261d24fc28a12f3e2ab9"
      hash4 = "dca33d6dacac0859ec2f3104485720fe2451e21eb06e676f4860ecc73a41e6f9"
      hash5 = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"
      id = "c2abe266-0c21-51aa-9426-46a4f59df937"
   strings:
      $x1 = "vG2eZ1KOeGd2n5fr" ascii fullword

      $s1 = "Windows %d(%d)-%s" ascii fullword
      $s2 = "auth_timestamp: " ascii fullword
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" wide fullword

      $op1 = { b8 c8 00 00 00 83 fb 01 44 0f 47 e8 41 8b c5 48 8b b4 24 e0 18 00 00 4c 8b a4 24 e8 18 00 00 48 8b 8d a0 17 00 00 48 33 cc }
      $op2 = { 33 d2 46 8d 04 b5 00 00 00 00 66 0f 1f 44 00 00 49 63 c0 41 ff c0 8b 4c 84 70 31 4c 94 40 48 ff c2 }
      $op3 = { 89 5c 24 50 0f 57 c0 c7 44 24 4c 04 00 00 00 c7 44 24 48 40 00 00 00 0f 11 44 24 60 0f 11 44 24 70 0f 11 45 80 0f 11 45 90 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 500KB and (
         1 of ($x*)
         or 2 of them
      )
      or (
         $x1 and 1 of ($s*)
         or 3 of them
      )
}

rule APT_UNC4736_NK_MAL_TAXHAUL_3CX_Apr23_1 {
   meta:
      description = "Detects TAXHAUL (AKA TxRLoader) malware used in the 3CX compromise by UNC4736"
      author = "Mandiant"
      date = "2023-03-04"
      score = 80
      reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
      id = "25a80f98-03d6-59e6-84e6-6d847a6c591e"
   strings:
      $p00_0 = {410f45fe4c8d3d[4]eb??4533f64c8d3d[4]eb??4533f64c8d3d[4]eb}
      $p00_1 = {4d3926488b01400f94c6ff90[4]41b9[4]eb??8bde4885c074}
   condition:
      uint16(0) == 0x5A4D and any of them
}
