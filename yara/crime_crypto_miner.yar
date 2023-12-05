
rule SUSP_LNX_SH_CryptoMiner_Indicators_Dec20_1 {
   meta:
      description = "Detects helper script used in a crypto miner campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
      date = "2020-12-31"
      hash1 = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"
      id = "e376e0e1-1490-5ad4-8ca2-d28ca1c0b51a"
   strings:
      $x1 = "miner running" fullword ascii
      $x2 = "miner runing" fullword ascii
      $x3 = " --donate-level 1 "
      $x4 = " -o pool.minexmr.com:5555 " ascii
   condition:
      filesize < 20KB and 1 of them
}

rule PUA_WIN_XMRIG_CryptoCoin_Miner_Dec20 {
   meta:
      description = "Detects XMRIG crypto coin miners"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
      date = "2020-12-31"
      hash1 = "b6154d25b3aa3098f2cee790f5de5a727fc3549865a7aa2196579fe39a86de09"
      id = "4dfb04e9-fbba-5a6f-ad20-d805025d2d74"
   strings:
      $x1 = "xmrig.exe" fullword wide
      $x2 = "xmrig.com" fullword wide
      $x3 = "* for x86, CRYPTOGAMS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and 2 of them or all of them
}
