/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-04
   Identifier: XMRIG
   Reference: https://github.com/xmrig/xmrig/releases
*/

/* Rule Set ----------------------------------------------------------------- */

rule XMRIG_Monero_Miner {
   meta:
      description = "Detects Monero mining software"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04"
      hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
      hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
      hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
      hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
   strings:
      $s1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $s3 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
      $s4 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 3000KB and 1 of them
}

rule XMRIG_Monero_Miner_Config {
   meta:
      description = "Auto-generated rule - from files config.json, config.json"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04"
      hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
      hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-06-28"
      hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
   strings:
      $x1 = "--multihash-factor=N              number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
      $s2 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
      $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
      $s4 = ".nicehash.com" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and ( 1 of ($x*) or 2 of them )
}

rule SUSP_XMRIG_String {
   meta:
      description = "Detects a suspicious XMRIG crypto miner executable string in filr"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-12-28"
      hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
   strings:
      $x1 = "xmrig.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}
