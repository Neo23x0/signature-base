/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-04
   Identifier: XMRIG
   Reference: https://github.com/xmrig/xmrig/releases
*/

/* Rule Set ----------------------------------------------------------------- */

rule XMRIG_Monero_Miner : HIGHVOL {
   meta:
      description = "Detects Monero mining software"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04"
      modified = "2022-11-10"
      modified = "2022-11-10"
      hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
      hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
      hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
      hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
      id = "71bf1b9c-c806-5737-83a9-d6013872b11d"
   strings:
      $s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s2 = "--cpu-affinity" ascii
      $s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
      $s4 = "password for mining server" fullword ascii
      $s5 = "XMRig/%s libuv/%s%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 10MB and 2 of them
}

rule XMRIG_Monero_Miner_Config {
   meta:
      description = "Auto-generated rule - from files config.json, config.json"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04"
      hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
      hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
      id = "374efe7f-9ef2-5974-8e24-f749183ab2d0"
   strings:
      $s2 = "\"cpu-affinity\": null,   // set process affinity to CPU core(s), mask \"0x3\" for cores 0 and 1" fullword ascii
      $s5 = "\"nicehash\": false                  // enable nicehash/xmrig-proxy support" fullword ascii
      $s8 = "\"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite" fullword ascii
   condition:
      ( uint16(0) == 0x0a7b or uint16(0) == 0x0d7b ) and filesize < 5KB and 1 of them
}

rule PUA_LNX_XMRIG_CryptoMiner {
   meta:
      description = "Detects XMRIG CryptoMiner software"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-06-28"
      modified = "2023-01-06"
      hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
      id = "bbdeff2e-68cc-5bbe-b843-3cba9c8c7ea8"
   strings:
      $x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
      $s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
      $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
      $s4 = ".nicehash.com" ascii
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and ( 1 of ($x*) or 2 of them )
}

rule SUSP_XMRIG_String {
   meta:
      description = "Detects a suspicious XMRIG crypto miner executable string in filr"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-28"
      hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
      id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"
   strings:
      $x1 = "xmrig.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}
