
rule APTGroupX_PlugXTrojanLoader_StringDecode {
   meta:
      author = "Jay DiMartino"
   	description = "Rule to detect PlugX Malware"
		score = 80
   	reference = "https://t.co/4xQ8G2mNap"
      hash1 = "0535e8c300204e257f0fa57630f386e9fcc8e779"
      hash2 = "088ebf9ccde958f32d11f4e7eb14f5332332f97d"
      hash3 = "0c999d0bffa007e9e6b6fe593933b52f40c75b3d"
      hash4 = "2f644e7131ec0a4f12ce04ba1e54d23856dbbfbf"
      hash5 = "3be9148ad132ca342d5fbabea1119a175ef1df7c"
      hash6 = "4c1ee94ec0e15491fc4f6b4095f67eee6309e62a"
      hash7 = "587af7ce05e61d4c312d6bae12ea380116b08d7e"
      hash8 = "5990efd83b5646a7ba419541d3a2c19260224ca3"
      hash9 = "67970367c250c44a5feb263843cf45fd91336df5"
      hash10 = "68f53f7188910a4cf67843aedd38c1523f1f2e7c"
      hash11 = "962dc7e0ad37286df012f623423ac4182fe791ca"
      hash12 = "aa0976906807af2e1b127608040aa3ef6e118a13"
      hash13 = "b170d015e32b39fa4ac15f94d58e45e65cd16d6c"
      hash14 = "c9b3d2cef3b34c7ee18fc2f60ff022965959613d"
      hash15 = "cd425ce7f3e4a823d9027780e1b439759c4dc665"
      hash16 = "d5e82513c6472d3826a22d9a15c05af8c0d33b58"
      hash17 = "d9b32084f27ef13001060e1dcee8a1a9e95d89a6"
      hash18 = "daa2d1cb9148b7ba5a86fa9ab593678e77c92672"
      hash19 = "e2c098a95d1c1f0e29f207af9c5ffc5bd69a92ee"
      hash20 = "ef8cf68dc3c80e9cb5a3fa0f92b544eab583812e"
      hash21 = "f0fc0a4e4e0748464caa6a202d0083cd33458677"
      hash22 = "fe1abe55529c1d6aa6b2a2f02d7e41ea58040feb"
   strings:
      $byte1 = { 8A [2-4] 8A [2-4] FF 05 00 30 00 10 [0-5] 2A [1-6] 80 [2-7] 02 [1-6] 88 0? }
      $byte2 = { 8B [2-4] 8A [2-4] FF 05 00 30 00 10 [0-5] 2A [1-6] 80 [2-7] 02 [1-6] 88 0? }
   condition:
      any of them
}
